#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <nmap.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include <nmap.h>

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
    strlcpy(error->u.dns.func_fail, func_fail, sizeof(error->u.dns.func_fail));
    strlcpy(error->u.dns.description, detail, sizeof(error->u.dns.description));
    error->error = errno;
}
int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data, struct sock_instance *sock);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

int ping_init(struct task_handle *data) {
    if (data->opts->src_port == 0 ||
        data->opts->usurp.arg) { // If src addr or port usurpation, ephemeral
                                 // socket is needed
        data->sock_eph.fd = socket_open_eph(data->opts, IPPROTO_TCP,
                                            &data->data.ping.saddr.sin_port);
        switch (data->sock_eph.fd) {
        default:
            break;
        case -2:
            data->flags.cancelled = 1;
            /* FALLTHRU */
        case -1:
            sys_error(data->error, "opening eph socket", "");
            data->data.ping.rslt->reason.type = REASON_ERROR;
            data->flags.error = 1;
            data->flags.done = 1;
            return (1);
        }
    }
    data->sock_main.fd = socket_open_tcp(data->opts, data->data.ping.daddr,
                                         &data->data.ping.saddr.sin_addr);
    switch (data->sock_main.fd) {
    default:
        break;
    case -2:
        data->flags.cancelled = 1;
        /* FALLTHRU */
    case -1:
        sys_error(data->error, "opening tcp socket",
                  inet_ntoa(data->data.ping.daddr));
        data->data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        return (1);
    }
    if (data->opts->usurp
            .arg) { // If addess usurpation, we replace local address by custom
        data->data.ping.saddr.sin_addr = data->opts->usurp.addr;
        data->data.ping.saddr.sin_port =
            htons(10000 +
                  (((uint16_t)rand()) %
                   (UINT16_MAX - 10000))); // Random port between [10000-65535]
    }
    if (data->opts->src_port) {
        data->data.ping.saddr.sin_port = htons(data->opts->src_port);
    }
    return (0);
}

int ping_packet_send(struct task_handle *data) {
    const size_t packet_size =
        sizeof(struct iphdr) + sizeof(struct tcphdr) + data->opts->size;
    char buffer[1024];
    ssize_t ret;
    // Build ip header
    // Build tcp header
    ret = send(data->sock_main.fd, buffer, packet_size, 0);
    if (ret < 0) {
        sys_error(data->error, "send", "sending initial packet");
        data->flags.error = 1;
        return (1);
    }
    data->flags.send_state = 1;
    data->timeout.tv_sec = 1;
    return (0);
}

int ping_packet_rcv(struct task_handle *data, struct sock_instance *sock) {
    (void)sock;
    (void)data;
    return (0);
}

int ping_packet_timeout(struct task_handle *data) {
    (void)data;
    data->data.ping.rslt->reason.type = REASON_NO_RESPONSE;
    data->data.ping.rslt->reason.ttl = 1; // ttl is time out
    return (1);
}

int ping_release(struct task_handle *data) {
    if (data->sock_eph.fd >= 0)
        close(data->sock_eph.fd);
    if (data->sock_icmp.fd >= 0)
        close(data->sock_icmp.fd);
    if (data->sock_main.fd >= 0)
        close(data->sock_main.fd);
    return (0);
}