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
    size_t pattern_idx; // Idx where pattern start (or headers end)
    struct timeval send_stamp_syn;
    struct timeval send_stamp_echo;
    struct packet packet;
};

int socket_open_eph(t_options *opts, int sock_type, uint16_t *port);
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr);
int socket_open_icmp(t_options *opts, struct in_addr daddr);

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
    error->u.icmp.iphdr = ctx->packet.buffer.iphdr;
    error->u.icmp.icmphdr = ctx->packet.buffer.icmp.icmphdr;
    if (ctx->packet.len >= 2 * sizeof(struct iphdr) + sizeof(struct icmphdr))
        error->u.icmp.org_iphdr =
            *(struct iphdr *)&ctx->packet.buffer.icmp.payload;
    if (ctx->packet.len >=
        2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8)
        memcpy(&error->u.icmp.detail,
               ctx->packet.buffer.icmp.payload + sizeof(struct iphdr), 8);
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
    ctx->packet.len = ctx->pattern_idx + data->opts->size;
    fill_pattern(data->opts->pattern, ctx->packet.buffer.raw + ctx->pattern_idx,
                 data->opts->size);
    init_iphdr(&ctx->packet.buffer.iphdr, ctx->packet.len, IPPROTO_TCP,
               data->opts);
    ctx->packet.buffer.iphdr.saddr = data->io_data.ping.saddr.sin_addr.s_addr;
    ctx->packet.buffer.iphdr.daddr = data->io_data.ping.daddr.s_addr;
    init_tcphdr(
        &ctx->packet.buffer.tcp.tcphdr,
        (struct tcp_params){.ack = 0,
                            .seq = 0,
                            .tcp_len = ctx->packet.len - sizeof(struct iphdr),
                            .flags = TH_SYN,
                            .sport = ntohs(data->io_data.ping.saddr.sin_port),
                            .dport = 80});
    calc_tcp_sum_pkt(ctx->packet.buffer.raw, ctx->packet.len);

    ret = send(data->sock_main.fd, ctx->packet.buffer.raw, ctx->packet.len, 0);
    if (ret < 0) {
        sys_error(data->error, "send", "sending tcp syn");
        data->flags.error = 1;
        return (1);
    } else if (ret == 0 || (size_t)ret != ctx->packet.len) {
        fprintf(stderr,
                "Warning: unexpected sent of %ld instead of %lu for tcp syn\n",
                ret, ctx->packet.len);
        return (0);
    }
    return (0);
}

static int send_echo(struct task_handle *data) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    ssize_t ret;

    ctx->pattern_idx = sizeof(struct iphdr) + sizeof(struct icmphdr);
    ctx->packet.len = ctx->pattern_idx + data->opts->size;
    fill_pattern(data->opts->pattern, ctx->packet.buffer.raw + ctx->pattern_idx,
                 data->opts->size);
    init_iphdr(&ctx->packet.buffer.iphdr, ctx->packet.len, IPPROTO_ICMP,
               data->opts);
    ctx->packet.buffer.iphdr.saddr = data->io_data.ping.saddr.sin_addr.s_addr;
    ctx->packet.buffer.iphdr.daddr = data->io_data.ping.daddr.s_addr;
    init_icmphdr(&ctx->packet.buffer.icmp.icmphdr, ICMP_ECHO,
                 (uint16_t)(gettid() % UINT16_MAX), 0);
    calc_icmp_sum_pkt(ctx->packet.buffer.raw, ctx->packet.len);

    ret = send(data->sock_icmp.fd, ctx->packet.buffer.raw, ctx->packet.len, 0);
    if (ret < 0) {
        sys_error(data->error, "send", "sending icmp echo");
        data->flags.error = 1;
        return (1);
    } else if (ret == 0 || (size_t)ret != ctx->packet.len) {
        fprintf(
            stderr,
            "Warning: unexpected sent of %ld instead of %lu for icmp echo\n",
            ret, ctx->packet.len);
        return (0);
    }
    return (0);
}

static int rcv_packet(struct task_handle *data, struct pollfd poll) {
    struct ping_context *ctx = (struct ping_context *)data->ctx;
    struct iovec iovec;
    ssize_t ret;

    if (poll.revents & POLLHUP) {
        fprintf(stderr, "Received POLLHUP\n");
        return (1);
    } else if (poll.revents & POLLERR) { // Incoming error
        iovec.iov_base = &ctx->packet.buffer.icmp_error.org_iphdr;
        iovec.iov_len = (char *)(&ctx->packet.buffer + 1) -
                        (char *)&ctx->packet.buffer.icmp_error.org_iphdr;
        ret = rcv_packet_msg(poll.fd, &ctx->packet, &iovec, MSG_ERRQUEUE);
    } else if (poll.revents & POLLIN) { // Incoming read
        iovec.iov_base = &ctx->packet.buffer.raw;
        iovec.iov_len = sizeof(ctx->packet.buffer);
        ret = rcv_packet_msg(poll.fd, &ctx->packet, &iovec, 0);
    }
    if (ret < 0) {
        sys_error(data->error, "recv", "reading incoming packet");
        data->flags.error = 1;
        return (1);
    } else if (ret == 0) {
        error(1, errno, "unexpected read of 0");
    } else {
        ctx->packet.len = ret;
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
    uint8_t proto = ctx->packet.buffer.iphdr.protocol;
    data->io_data.ping.rslt->reason.rtt =
        compute_rtt(ctx->send_stamp_syn, ctx->packet.stamp);

    switch (proto) {
    case IPPROTO_TCP:
        // we probably dont need to actually check the content of the returned
        // tcp header.
        if (ctx->packet.buffer.tcp.tcphdr.th_flags & TH_RST)
            data->io_data.ping.rslt->reason.type = REASON_RST;
        else if (ctx->packet.buffer.tcp.tcphdr.th_flags & TH_SYN)
            data->io_data.ping.rslt->reason.type = REASON_SYN_ACK;
        else
            data->io_data.ping.rslt->reason.type = REASON_UNKNOWN;
        data->io_data.ping.rslt->reason.ttl = ctx->packet.buffer.iphdr.ttl;
        return (1);

    case IPPROTO_ICMP:
        switch (ctx->packet.buffer.icmp.icmphdr.type) {
        case ICMP_ECHO:
        case ICMP_TIMESTAMP:
            break;
        case ICMP_ECHOREPLY:
        case ICMP_TIMESTAMPREPLY:
            data->io_data.ping.rslt->reason.rtt =
                compute_rtt(ctx->send_stamp_echo, ctx->packet.stamp);
            data->io_data.ping.rslt->reason.type = REASON_ICMP_REPLY;
            data->io_data.ping.rslt->reason.ttl = ctx->packet.buffer.iphdr.ttl;
            return (1);
        case ICMP_TIME_EXCEEDED:
            data->io_data.ping.rslt->reason.ttl = ctx->packet.buffer.iphdr.ttl;
            data->io_data.ping.rslt->reason.type = REASON_TIME_EXCEEDED;
            icmp_error(data->error, ctx);
            return (1);
        case ICMP_DEST_UNREACH:
            data->io_data.ping.rslt->reason.ttl = ctx->packet.buffer.iphdr.ttl;
            if (ctx->packet.buffer.icmp.icmphdr.code == ICMP_HOST_UNREACH) {
                data->io_data.ping.rslt->reason.type = REASON_HOST_UNREACH;
                return (1);
            } else if (ctx->packet.buffer.icmp.icmphdr.code ==
                       ICMP_PORT_UNREACH) {
                data->io_data.ping.rslt->reason.type = REASON_PORT_UNREACH;
                return (1);
            }
            /* FALLTHRU */
        case ICMP_REDIRECT:
        case ICMP_SOURCE_QUENCH:
        default:
            data->io_data.ping.rslt->reason.ttl = ctx->packet.buffer.iphdr.ttl;
            data->io_data.ping.rslt->reason.type = REASON_UNKNOWN;
            icmp_error(data->error, ctx);
            return (1);
        }
        break;

    default:
        fprintf(stderr, "Unexpected protocol received\n");
        print_verbose_packet(ctx->packet.buffer.raw, ctx->packet.len);
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
        case -1:
            data->flags.cancelled = 1;
            /* FALLTHRU */
        case -2:
            sys_error(data->error, "opening eph socket", "");
            data->io_data.ping.rslt->reason.type = REASON_ERROR;
            data->flags.error = 1;
            data->flags.done = 1;
            free(data->ctx);
            return (1);
        }
    }
    data->sock_icmp.fd = socket_open_icmp(data->opts, data->io_data.ping.daddr);
    switch (data->sock_icmp.fd) {
    default:
        break;
    case -1:
    case -2:
        if (data->sock_eph.fd >= 0)
            close(data->sock_eph.fd);
        sys_error(data->error, "opening icmp socket",
                  inet_ntoa(data->io_data.ping.daddr));
        data->io_data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        free(data->ctx);
        return (1);
    }
    data->sock_main.fd = socket_open_tcp(data->opts, data->io_data.ping.daddr,
                                         &data->io_data.ping.saddr.sin_addr);
    switch (data->sock_main.fd) {
    default:
        break;
    case -1:
        data->flags.cancelled = 1;
        /* FALLTHRU */
    case -2:
        if (data->sock_eph.fd >= 0)
            close(data->sock_eph.fd);
        if (data->sock_icmp.fd >= 0)
            close(data->sock_icmp.fd);
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
        gettimeofday(&ctx->send_stamp_syn, NULL);
        if (send_syn(data))
            return (1);
        if (data->opts->trace_packet)
            print_packet_short(ctx->packet.buffer.raw, "SND");
        ctx->tcp_state = TCPSTATE_SYN_SENT;
        data->timeout = (struct timeval){.tv_sec = PING_TIMEOUT};
        data->flags.send_state = 1;
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

    switch (ctx->icmp_state) {
    case ICMPSTATE_START: // SEND icmp echo
        gettimeofday(&ctx->send_stamp_echo, NULL);
        if (send_echo(data))
            return (1);
        if (data->opts->trace_packet)
            print_packet_short(ctx->packet.buffer.raw, "SND");
        data->flags.send_state = 1;
        data->timeout = (struct timeval){.tv_sec = PING_TIMEOUT};
        ctx->icmp_state = ICMPSTATE_ECHO_SENT;
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
        // print_verbose_packet(ctx->packet.buffer.raw, ctx->packet.len);
        return (1);
    }
    if (data->opts->trace_packet)
        print_packet_short(ctx->packet.buffer.raw, "RCV");
    if (poll.fd == data->sock_main.fd) { // TCP
        switch (ctx->tcp_state) {
        case TCPSTATE_START:
            fprintf(stderr, "Received incoming packet but nothing was sent");
            print_verbose_packet(ctx->packet.buffer.raw, ctx->packet.len);
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
            print_verbose_packet(ctx->packet.buffer.raw, ctx->packet.len);
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
    data->io_data.ping.rslt->reason.ttl = 0; // ttl is time out
    data->io_data.ping.rslt->reason.rtt = 0.f;
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