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
        TCPSTATE_RCV,
        TCPSTATE_RST_SENT
    } tcp_state;
    enum icmp_state {
        ICMPSTATE_START = 0,
        ICMPSTATE_ECHO_SENT,
        ICMPSTATE_RCV,
    } icmp_state;
    size_t len;         // Variable
    size_t pattern_idx; // Idx where pattern start (or headers end)
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

int socket_open_eph(t_options *opts, int protocol, uint16_t *port);
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
int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data, struct sock_instance *sock);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

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
    // ft_hexdump_color_zone(ctx->buffer.raw, ctx->len, 1, 0, 8);
    print_verbose_packet(ctx->buffer.raw, ctx->len);

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
    if (data->opts->src_port == 0 ||
        data->opts->usurp.arg) { // If src addr or port usurpation, ephemeral
                                 // socket is needed
        data->sock_eph.fd = socket_open_eph(data->opts, IPPROTO_IP,
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
    if (data->opts->usurp
            .arg) { // If addess usurpation, we replace local address by custom
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
        if (send_syn(data))
            return (1);
        ctx->tcp_state = TCPSTATE_SYN_SENT;
        data->timeout = (struct timeval){.tv_sec = 3};
        break;
    case TCPSTATE_SYN_SENT: // Maybe there is still an ICMP echo request to send
        if (ctx->icmp_state != ICMPSTATE_START) {
            fprintf(stderr,
                    "Warning: ping_packet_send() called but tcp SYN sent and "
                    "ICMP echo sent also. Setting sent_state to 1.");
            data->flags.send_state = 1;
            return (0);
        }
        break;
    case TCPSTATE_RCV: // SEND tcp reset

        return (1);         // DONE
    case TCPSTATE_RST_SENT: // Unlikely
        if (ctx->icmp_state != ICMPSTATE_START) {
            fprintf(stderr,
                    "Warning: ping_packet_send() called but tcp RST sent and "
                    "ICMP echo sent also. Setting sent_state to 1.");
            data->flags.send_state = 1;
            return (0);
        }
        break;
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

int ping_packet_rcv(struct task_handle *data, struct sock_instance *sock) {
    (void)sock;
    (void)data;
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