#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <nmap.h>
#include <protocol.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

struct ping_context {
    // struct tcp_data tcp_data;
    enum tcp_state {
        TCPSTATE_START = 0,
        TCPSTATE_SYN_SENT,
        TCPSTATE_RCV, // Never set
        // rst is sent by kernel, so no need to send it
    } tcp_state;
    enum icmp_state {
        ICMPSTATE_START = 0,
        ICMPSTATE_ECHO_SENT,
        ICMPSTATE_RCV, // Never set
    } icmp_state;
    size_t len;         // Variable
    size_t pattern_idx; // Idx where pattern start (or headers end)
    struct timeval send_stamp;
    struct timeval rcv_stamp;
    union {
        struct {
            struct iphdr iphdr;
            union {
                struct {
                    struct tcphdr tcphdr;
                    char payload[];
                } tcp;
                struct {
                    struct icmphdr icmphdr;
                    char payload[];
                } icmp;
            };
        };
        char raw[1024];
    } buffer;
};

int socket_open_eph(t_options *opts, int sock_type, uint16_t *port);
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr);

static void sys_error(struct nmap_error **error_ptr, const char *func_fail,
                      const char *detail) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_SYS;
    ft_strlcpy(error->u.dns.func_fail, func_fail,
               sizeof(error->u.dns.func_fail));
    ft_strlcpy(error->u.dns.description, detail,
               sizeof(error->u.dns.description));
    error->error = errno;
}

static void icmp_error(struct nmap_error **error_ptr,
                       struct ping_context *ctx) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_ICMP;
    error->error = 0;
    error->u.icmp.iphdr = ctx->buffer.iphdr;
    error->u.icmp.icmphdr = ctx->buffer.icmp.icmphdr;
    if (ctx->len >= 2 * sizeof(struct iphdr) + sizeof(struct icmphdr))
        error->u.icmp.org_iphdr = *(struct iphdr *)&ctx->buffer.icmp.payload;
    if (ctx->len >= 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8)
        memcpy(&error->u.icmp.detail,
               ctx->buffer.icmp.payload + sizeof(struct iphdr), 8);
}

int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data, struct pollfd sock);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

float compute_rtt(struct timeval start, struct timeval end);

static int send_syn(struct task_handle *data) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    ssize_t ret;

    ctx->pattern_idx = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ctx->len = ctx->pattern_idx + data->opts->size;
    fill_pattern(data->opts->pattern, ctx->buffer.raw + ctx->pattern_idx,
                 data->opts->size);
    init_iphdr(&ctx->buffer.iphdr, ctx->len, IPPROTO_TCP, data->opts);
    ctx->buffer.iphdr.saddr = data->io_data.ping.saddr.sin_addr.s_addr;
    ctx->buffer.iphdr.daddr = data->io_data.ping.daddr.s_addr;
    init_tcphdr(
        &ctx->buffer.tcp.tcphdr,
        (struct tcp_params){.ack = 0,
                            .seq = 0,
                            .tcp_len = ctx->len - sizeof(struct iphdr),
                            .flags = TH_SYN,
                            .sport = ntohs(data->io_data.ping.saddr.sin_port),
                            .dport = 80});
    calc_tcp_sum_pkt(ctx->buffer.raw, ctx->len);

    ret = send(data->sock_main.fd, ctx->buffer.raw, ctx->len, 0);
    if (ret < 0) {
        sys_error(data->error, "send", "sending tcp syn");
        data->flags.error = 1;
        data->flags.cancelled = 1;
        return (1);
    } else if (ret == 0 || (size_t)ret != ctx->len) {
        fprintf(stderr,
                "Warning: unexpected sent of %ld instead of %lu for tcp syn\n",
                ret, ctx->len);
        return (0);
    }
    return (0);
}

static int rcv_packet_pollin(struct task_handle *data, int fd) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    ssize_t ret;

    ret = recv(fd, ctx->buffer.raw, sizeof(ctx->buffer.raw), 0);
    if (ret < 0) {
        sys_error(data->error, "recv", "reading incoming packet");
        data->flags.error = 1;
        data->flags.cancelled = 1;
        return (1);
    } else if (ret == 0) {
        error(1, errno, "unexpected read of 0");
    }
    gettimeofday(&ctx->rcv_stamp, NULL);
    ctx->len = (size_t)ret;
    return (0);
}

static int rcv_packet_pollerr(struct task_handle *data, int fd) {
    printf("NOT IMPLEMENTED\n");
    (void)data;
    (void)fd;
    return (0);
}

static int rcv_packet(struct task_handle *data, struct pollfd poll) {
    if (poll.revents & POLLHUP) {
        fprintf(stderr, "Received POLLHUP\n");
        return (1);
    } else if (poll.revents & POLLERR) { // Incoming error
        return (rcv_packet_pollerr(data, poll.fd));
    } else if (poll.revents & POLLIN) { // Incoming read
        return (rcv_packet_pollin(data, poll.fd));
    }
    return (0);
}

/// @brief Unkown protocol are ignored (task doesn't stop), unexpected ICMP
/// errors are stored and the task stops.
/// Any TCP response make the task stop.
/// @param data
/// @return
static int handle_packet_rcv(struct task_handle *data) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    uint8_t proto = ctx->buffer.iphdr.protocol;
    data->io_data.ping.rslt->reason.rtt =
        compute_rtt(ctx->send_stamp, ctx->rcv_stamp);

    switch (proto) {
    case IPPROTO_TCP:
        // we probably dont need to actually check the content of the returned
        // tcp header.
        if (ctx->buffer.tcp.tcphdr.th_flags & TH_RST)
            data->io_data.ping.rslt->reason.type = REASON_RST;
        else if (ctx->buffer.tcp.tcphdr.th_flags & TH_SYN)
            data->io_data.ping.rslt->reason.type = REASON_SYN_ACK;
        else
            data->io_data.ping.rslt->reason.type = REASON_UNKNOWN;
        data->io_data.ping.rslt->reason.ttl = ctx->buffer.iphdr.ttl;
        return (1);

    case IPPROTO_ICMP:
        switch (ctx->buffer.icmp.icmphdr.type) {
        case ICMP_ECHO:
            break;
        case ICMP_ECHOREPLY:
            data->io_data.ping.rslt->reason.type = REASON_ICMP_REPLY;
            data->io_data.ping.rslt->reason.ttl = ctx->buffer.iphdr.ttl;
            return (1);
        case ICMP_DEST_UNREACH:
            data->io_data.ping.rslt->reason.ttl = ctx->buffer.iphdr.ttl;
            if (ctx->buffer.icmp.icmphdr.code == ICMP_HOST_UNREACH) {
                data->io_data.ping.rslt->reason.type = REASON_HOST_UNREACH;
                return (1);
            } else if (ctx->buffer.icmp.icmphdr.code == ICMP_PORT_UNREACH) {
                data->io_data.ping.rslt->reason.type = REASON_PORT_UNREACH;
                return (1);
            }
            /* FALLTHRU */
        default:
            data->io_data.ping.rslt->reason.ttl = ctx->buffer.iphdr.ttl;
            data->io_data.ping.rslt->reason.type = REASON_UNKNOWN;
            icmp_error(data->error, ctx);
            return (1);
        }
        break;

    default:
        fprintf(stderr, "Unexpected protocol received\n");
        print_verbose_packet(ctx->buffer.raw, ctx->len);
        return (0);
    }
    return (0);
}

int ping_init(struct task_handle *data) {
    data->ctx = calloc(1, sizeof(struct ping_context));
    if (data->ctx == NULL) {
        sys_error(data->error, "allocating task context", "");
        data->io_data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        data->flags.cancelled = 1;
        data->flags.done = 1;
        return (1);
    }
    // unless port/addr usurpation, ephemeral socket is needed
    if (data->opts->src_port == 0 && data->opts->usurp.arg == NULL) {
        data->sock_eph.fd = socket_open_eph(data->opts, SOCK_STREAM,
                                            &data->io_data.ping.saddr.sin_port);
        switch (data->sock_eph.fd) {
        default:
            break;
        case -2:
            data->flags.cancelled = 1;
            /* FALLTHRU */
        case -1:
            sys_error(data->error, "opening eph socket", "");
            data->io_data.ping.rslt->reason.type = REASON_ERROR;
            data->flags.error = 1;
            data->flags.done = 1;
            free(data->ctx);
            return (1);
        }
    }
    data->sock_main.fd = socket_open_tcp(data->opts, data->io_data.ping.daddr,
                                         &data->io_data.ping.saddr.sin_addr);
    switch (data->sock_main.fd) {
    default:
        break;
    case -2:
        data->flags.cancelled = 1;
        /* FALLTHRU */
    case -1:
        if (data->sock_eph.fd >= 0)
            close(data->sock_eph.fd);
        sys_error(data->error, "opening tcp socket",
                  inet_ntoa(data->io_data.ping.daddr));
        data->io_data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        free(data->ctx);
        return (1);
    }
    if (data->opts->usurp.arg) { // If addess usurpation, we replace local
                                 // address by custom
        data->io_data.ping.saddr.sin_addr = data->opts->usurp.addr;
        data->io_data.ping.saddr.sin_port =
            htons(10000 +
                  (((uint16_t)rand()) %
                   (UINT16_MAX - 10000))); // Random port between [10000-65535]
    }
    if (data->opts->src_port) {
        data->io_data.ping.saddr.sin_port = htons(data->opts->src_port);
    }

    return (0);
}

int ping_packet_send(struct task_handle *data) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    switch (ctx->tcp_state) {
    case TCPSTATE_START: // SEND tcp syn
        gettimeofday(&ctx->send_stamp, NULL);
        if (send_syn(data))
            return (1);
        ctx->tcp_state = TCPSTATE_SYN_SENT;
        data->timeout = (struct timeval){.tv_sec = PING_TIMEOUT};
        break;
    case TCPSTATE_SYN_SENT: // Maybe there is still an ICMP echo request to
                            // send
        if (ctx->icmp_state != ICMPSTATE_START) {
            fprintf(stderr,
                    "Warning: ping_packet_send() called but tcp SYN sent and "
                    "ICMP echo sent also. Setting sent_state to 1.");
            data->flags.send_state = 1;
            return (0);
        }
        break;
    case TCPSTATE_RCV: // UNLIKELY
        return (1);    // DONE
    default:
        error(1, errno, "invalid tcp state");
    }
    data->flags.send_state = 1;

    return (0); // DISABLE ICMP FOR NOW

    switch (ctx->icmp_state) {
    case ICMPSTATE_START: // SEND icmp echo
        break;

    case ICMPSTATE_ECHO_SENT:
        if (ctx->tcp_state != TCPSTATE_START) {
            fprintf(stderr,
                    "Warning: ping_packet_send() called but tcp SYN sent and "
                    "ICMP echo sent also. Setting sent_state to 1.");
            data->flags.send_state = 1;
            return (0);
        }
        break;

    case ICMPSTATE_RCV:
        return (1); // NOTHING TO DO !!!

    default:
        error(1, errno, "invalid icmp state");
    }
    return (0);
}

int ping_packet_rcv(struct task_handle *data, struct pollfd poll) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;

    if (rcv_packet(data, poll)) {
        print_verbose_packet(ctx->buffer.raw, ctx->len);
        return (1);
    }
    if (poll.fd == data->sock_main.fd) { // TCP
        switch (ctx->tcp_state) {
        case TCPSTATE_START:
            fprintf(stderr, "Received incoming packet but nothing was sent");
            print_verbose_packet(ctx->buffer.raw, ctx->len);
            break;
        case TCPSTATE_SYN_SENT: // Handle packet
            if (handle_packet_rcv(data))
                return (1);
            break;
        case TCPSTATE_RCV: // UNLIKELY
            return (1);
        default:
            error(1, errno, "invalid tcp state");
        }
    } else if (poll.fd == data->sock_icmp.fd) { // ICMP
        switch (ctx->icmp_state) {
        case ICMPSTATE_START:
            fprintf(stderr, "Received incoming packet but nothing was sent");
            print_verbose_packet(ctx->buffer.raw, ctx->len);
            break;
        case ICMPSTATE_ECHO_SENT: // Handle packet
            if (handle_packet_rcv(data))
                return (1);
            break;
        case ICMPSTATE_RCV: // UNLIKELY
            return (1);
        default:
            error(1, errno, "invalid tcp state");
        }
    } else {
        error(1, errno, "called ping_packet_rcv() for unrelated socket\n");
    }
    return (0);
}

int ping_packet_timeout(struct task_handle *data) {
    (void)data;
    data->io_data.ping.rslt->reason.type = REASON_NO_RESPONSE;
    data->io_data.ping.rslt->reason.ttl = 1; // ttl is time out
    return (1);
}

int ping_release(struct task_handle *data) {
    if (data->sock_eph.fd >= 0)
        close(data->sock_eph.fd);
    if (data->sock_icmp.fd >= 0)
        close(data->sock_icmp.fd);
    if (data->sock_main.fd >= 0)
        close(data->sock_main.fd);
    if (data->ctx)
        free(data->ctx);
    return (0);
}