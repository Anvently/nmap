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

/*
TCP SCAN IMPLEMENTATION (SYN, ACK, NULL, FIN, XMAS)

@note: All probe are sent together
@note: For each probe received, corresponding port result in
data->io_data.tcp.result is found by iterating every port. So it's faster if the
iterated vector is sorted and if the vector is not too long.
@note: unrelated probes are received if timeout of a previous task was too short
and the task returned when the response packet is received. Such packet are
ignored and do not trigger any error.
*/

struct tcp_context {
    // struct scan_data scan_data;
    enum tcp_state {
        TCPSTATE_START = 0,
        TCPSTATE_SENT,
    } state;            // shared by all port (probes are sent together)
    size_t pattern_idx; // Idx where pattern start (or headers end)
    struct packet packet;
    uint16_t waiting; // Count how many port are waiting for a response
    struct timeval send_stamp;
};

void nmap_sys_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail);
void nmap_icmp_error(struct nmap_error **error_ptr, struct packet *packet);
void nmap_packet_error(struct nmap_error **error_ptr, const char *context,
                       struct packet *packet);

int tcp_packet_send(struct task_handle *data);
int tcp_packet_rcv(struct task_handle *data, struct pollfd sock);
int tcp_init(struct task_handle *data);
int tcp_packet_timeout(struct task_handle *data);
int tcp_release(struct task_handle *data);

int socket_open_eph(t_options *opts, int sock_type, uint16_t *port);
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr);
int socket_clear_error(int socket);

static void resolve_state(struct tcp_context *ctx, enum scan_type scan_type,
                          struct port_info *port);

float timeval_to_ms(struct timeval tv);

int tcp_init(struct task_handle *data) {
    data->ctx = calloc(1, sizeof(struct tcp_context));
    if (data->ctx == NULL) {
        nmap_sys_error(data->error, "allocating task context", "");
        data->flags.error = 1;
        data->flags.cancelled = 1;
        data->flags.done = 1;
        return (1);
    }
    // unless port/addr usurpation, ephemeral socket is needed
    if (data->opts->src_port == 0 && data->opts->usurp.arg == NULL) {
        data->sock_eph.fd = socket_open_eph(data->opts, SOCK_STREAM,
                                            &data->io_data.tcp.saddr.sin_port);
        switch (data->sock_eph.fd) {
        default:
            break;
        case -1:
            data->flags.cancelled = 1;
            /* FALLTHRU */
        case -2:
            nmap_sys_error(data->error, "opening eph socket", "");
            data->flags.error = 1;
            data->flags.done = 1;
            free(data->ctx);
            return (1);
        }
    }
    data->sock_main.fd = socket_open_tcp(data->opts, data->io_data.tcp.daddr,
                                         &data->io_data.tcp.saddr.sin_addr);
    switch (data->sock_main.fd) {
    default:
        break;
    case -1:
        data->flags.cancelled = 1;
        /* FALLTHRU */
    case -2:
        if (data->sock_eph.fd >= 0)
            close(data->sock_eph.fd);
        nmap_sys_error(data->error, "opening tcp socket",
                       inet_ntoa(data->io_data.tcp.daddr));
        data->flags.error = 1;
        free(data->ctx);
        return (1);
    }
    if (data->opts->usurp.arg) { // If addess usurpation, we replace local
                                 // address by custom
        data->io_data.tcp.saddr.sin_addr = data->opts->usurp.addr;
        data->io_data.tcp.saddr.sin_port =
            htons(10000 +
                  (((uint16_t)rand()) %
                   (UINT16_MAX - 10000))); // Random port between [10000-65535]
    }
    if (data->opts->src_port) {
        data->io_data.tcp.saddr.sin_port = htons(data->opts->src_port);
    }

    return (0);
}

int tcp_packet_timeout(struct task_handle *data) {
    struct port_info *port_info;

    for (uint16_t i = 0; i < data->io_data.tcp.nbr_port; i++) {
        port_info = &data->io_data.tcp.ports[i];
        if (port_info->state != PORT_SCANNING) {
            continue;
        }
        port_info->reason.type = REASON_NO_RESPONSE;
        port_info->reason.ttl = 0; // ttl is time out
        port_info->reason.rtt = timeval_to_ms(data->base_timeout);
        resolve_state((struct tcp_context *)data->ctx, data->scan_type,
                      port_info);
    }
    return (1);
}

int tcp_release(struct task_handle *data) {
    if (data->sock_eph.fd >= 0)
        close(data->sock_eph.fd);
    if (data->sock_main.fd >= 0)
        close(data->sock_main.fd);
    if (data->ctx)
        free(data->ctx);
    return (0);
}

static void resolve_state(struct tcp_context *ctx, enum scan_type scan_type,
                          struct port_info *port) {
    switch (scan_type) {
    case SCAN_SYN:
        switch (port->reason.type) {
        case REASON_SYN_ACK:
            port->state = PORT_OPENED;
            break;

        case REASON_RST:
            port->state = PORT_CLOSED;
            break;

        // TIME_EXCEEDED MAY ALSO COUNT AS FILTERED
        case REASON_NO_RESPONSE:
        case REASON_PORT_UNREACH:
        case REASON_HOST_UNREACH:
        case REASON_TIME_EXCEEDED:
        case REASON_UNREACH:
            port->state = PORT_FILTERED;
            break;

        case REASON_ERROR:
        default:
            nmap_packet_error(&port->error, "unexpected response",
                              &ctx->packet);
            port->state = PORT_ERROR;
            break;
        }
        break;

    case SCAN_ACK:
        switch (port->reason.type) {

        case REASON_RST:
            port->state = PORT_UNFILTERED;
            break;

        // TIME_EXCEEDED MAY ALSO COUNT AS FILTERED
        case REASON_NO_RESPONSE:
        case REASON_PORT_UNREACH:
        case REASON_HOST_UNREACH:
        case REASON_UNREACH:
            port->state = PORT_FILTERED;
            break;

        case REASON_ERROR:
        default:
            nmap_packet_error(&port->error, "unexpected response",
                              &ctx->packet);
            port->state = PORT_ERROR;
            break;
        }
        break;

    case SCAN_NULL:
    case SCAN_FIN:
    case SCAN_XMAS:
        switch (port->reason.type) {
        case REASON_RST:
            port->state = PORT_CLOSED;
            break;

        case REASON_NO_RESPONSE:
            port->state = PORT_OPEN_FILTERED;
            break;

        // TIME_EXCEEDED MAY ALSO COUNT AS FILTERED
        case REASON_PORT_UNREACH:
        case REASON_HOST_UNREACH:
        case REASON_UNREACH:
            port->state = PORT_FILTERED;
            break;

        case REASON_ERROR:
        default:
            nmap_packet_error(&port->error, "unexpected response",
                              &ctx->packet);
            port->state = PORT_ERROR;
            break;
        }
        break;

    default:
        break;
    }
}

static uint8_t get_tcp_flags(enum scan_type type) {
    switch (type) {
    case SCAN_SYN:
        return (TH_SYN);
    case SCAN_ACK:
        return (TH_ACK);
    case SCAN_FIN:
        return (TH_FIN);
    case SCAN_XMAS:
        return (TH_FIN | TH_PUSH | TH_URG);
    case SCAN_NULL:
    default:
        return (0);
    }
}

/// @brief  Return the number of sent packet
/// @param data
/// @return
static int send_pkt_to_port(struct task_handle *data, struct port_info *port) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;
    ssize_t ret = 0;

    ctx->pattern_idx = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ctx->packet.len = ctx->pattern_idx + data->opts->size;
    fill_pattern(data->opts->pattern, ctx->packet.buffer.raw + ctx->pattern_idx,
                 data->opts->size);
    init_iphdr(&ctx->packet.buffer.iphdr, ctx->packet.len, IPPROTO_TCP,
               data->opts);
    ctx->packet.buffer.iphdr.saddr = data->io_data.tcp.saddr.sin_addr.s_addr;
    ctx->packet.buffer.iphdr.daddr = data->io_data.tcp.daddr.s_addr;
    init_tcphdr(
        &ctx->packet.buffer.tcp.tcphdr,
        (struct tcp_params){.ack = 0,
                            .seq = 0,
                            .tcp_len = ctx->packet.len - sizeof(struct iphdr),
                            .flags = get_tcp_flags(data->scan_type),
                            .sport = ntohs(data->io_data.tcp.saddr.sin_port),
                            .dport = port->port});
    calc_tcp_sum_pkt(ctx->packet.buffer.raw, ctx->packet.len);

    socket_clear_error(data->sock_main.fd);
    ret = send(data->sock_main.fd, ctx->packet.buffer.raw, ctx->packet.len, 0);
    if (ret < 0) {
        nmap_sys_error(&port->error, "send", "sending tcp packet");
        return (1);
    } else if (ret == 0 || (size_t)ret != ctx->packet.len) {
        fprintf(stderr,
                "Warning: unexpected sent of %ld instead of %lu for tcp\n", ret,
                ctx->packet.len);
        return (0);
    }
    return (0);
}

int tcp_packet_send(struct task_handle *data) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;
    struct port_info *port;

    switch (ctx->state) {
    case TCPSTATE_START: // SEND tcp syn
        gettimeofday(&ctx->send_stamp, NULL);
        for (uint16_t i = 0; i < data->io_data.tcp.nbr_port; i++) {
            port = &data->io_data.tcp.ports[i];
            if (send_pkt_to_port(data, port) == 0) {
                ctx->waiting++;
                if (data->opts->trace_packet)
                    print_packet_short(ctx->packet.buffer.raw, "SND");
            }
        }
        if (ctx->waiting == 0) { // No packet was sent, error
            data->flags.error = 1;
            return (1);
        }
        ctx->state = TCPSTATE_SENT;
        data->flags.send_state = 1;
        break;
    case TCPSTATE_SENT:
        fprintf(stderr, "Warning: tcp_packet_send() called but pkts were "
                        "already sent. Setting sent_state to 1.");
        data->flags.send_state = 1;
        return (0);
    default:
        error(1, errno, "invalid tcp state");
    }
    return (0);
}

static int rcv_packet(struct task_handle *data, struct pollfd poll) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;
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
        nmap_sys_error(data->error, "recv", "reading incoming packet");
        data->flags.error = 1;
        return (1);
    } else if (ret == 0) {
        error(1, errno, "unexpected read of 0");
    } else {
        ctx->packet.len = ret;
    }
    return (0);
}

static struct port_info *
find_port(uint16_t nbr_port, struct port_info ports[nbr_port], uint16_t port) {
    for (uint16_t i = 0; i < nbr_port; i++) {
        if (ports[i].port == port)
            return (&ports[i]);
        if (ports[i].port > port) // port are sorted
            return (NULL);
    }
    return (NULL);
}

void print_nmap_error(struct nmap_error *error);

static struct port_info *demul_packet(struct task_handle *data) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;
    struct port_info *port;

    switch (ctx->packet.buffer.iphdr.protocol) {
    case IPPROTO_TCP:
        port = find_port(data->io_data.tcp.nbr_port, data->io_data.tcp.ports,
                         ntohs(ctx->packet.buffer.tcp.tcphdr.th_sport));
        if (port->state != PORT_SCANNING)
            return (NULL);
        break;

    case IPPROTO_ICMP:
        port = find_port(
            data->io_data.tcp.nbr_port, data->io_data.tcp.ports,
            ntohs(((struct tcphdr *)ctx->packet.buffer.icmp_error.payload)
                      ->th_dport));
        break;

    default:
        nmap_packet_error(data->error, "invalid protocol", &ctx->packet);
        data->flags.error = 1;
        return (NULL);
    }
    if (port == NULL) {
        if (data->opts->verbose > 1) {
            nmap_packet_error(data->error, "no port match", &ctx->packet);
            print_nmap_error(*data->error);
            printf("Rtt factor is probably too small, try again with "
                   "--rtt-timeout=%f\n",
                   data->opts->rtt_factor * 1.5f);
            free(*data->error);
            *data->error = NULL;
        }
    }
    return (port);
}

float compute_rtt(struct timeval start, struct timeval end);

/// @brief
/// @param data
/// @param port
static void handle_rcv_packet(struct task_handle *data,
                              struct port_info *port) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;

    port->reason.ttl = ctx->packet.buffer.iphdr.ttl;
    port->reason.rtt = compute_rtt(ctx->send_stamp, ctx->packet.stamp);
    switch (ctx->packet.buffer.iphdr.protocol) {
    case IPPROTO_TCP:
        if (ctx->packet.buffer.tcp.tcphdr.th_flags & TH_SYN)
            port->reason.type = REASON_SYN_ACK;
        else if (ctx->packet.buffer.tcp.tcphdr.th_flags & TH_RST)
            port->reason.type = REASON_RST;
        else {
            nmap_packet_error(&port->error, "unexpected flags", &ctx->packet);
            port->reason.type = REASON_ERROR;
        }
        break;

    case IPPROTO_ICMP:
        switch (ctx->packet.buffer.icmp_error.icmphdr.type) {
        // case ICMP_ECHO
        case ICMP_UNREACH:
            if (ctx->packet.buffer.icmp_error.icmphdr.code == ICMP_UNREACH_PORT)
                port->reason.type = REASON_PORT_UNREACH;
            else if (ctx->packet.buffer.icmp_error.icmphdr.code ==
                     ICMP_UNREACH_HOST)
                port->reason.type = REASON_HOST_UNREACH;
            else
                port->reason.type = REASON_UNREACH;
            break;

        case ICMP_TIME_EXCEEDED:
            port->reason.type = REASON_TIME_EXCEEDED;
            break;

        default:
            nmap_icmp_error(&port->error, &ctx->packet);
            port->reason.type = REASON_ERROR;
            break;
        }
        break;

    default:
        break;
    }
    resolve_state(ctx, data->scan_type, port);
}

int tcp_packet_rcv(struct task_handle *data, struct pollfd poll) {
    struct tcp_context *ctx = (struct tcp_context *)data->ctx;
    struct port_info *port;

    if (rcv_packet(data, poll)) {
        return (1);
    }
    if (data->opts->trace_packet)
        print_packet_short(ctx->packet.buffer.raw, "RCV");
    if (poll.fd == data->sock_main.fd) { // TCP
        switch (ctx->state) {
        case TCPSTATE_START:
            fprintf(stderr, "Received incoming packet but nothing was sent");
            print_verbose_packet(ctx->packet.buffer.raw, ctx->packet.len);
            break;
        case TCPSTATE_SENT: // Handle packet
            port = demul_packet(data);
            if (port == NULL) {
                break;
            }
            handle_rcv_packet(data, port);
            if (--ctx->waiting == 0) // all port scanned
                return (1);
            break;
        default:
            error(1, errno, "invalid tcp state");
        }
    } else {
        error(1, errno, "called tcp_packet_rcv() for unrelated socket\n");
    }

    return (0);
}
