#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <nmap.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include <nmap.h>

int socket_open_eph(t_options *opts, int protocol);
int socket_open_tcp(t_options *opts);

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
int ping_packet_rcv(struct task_handle *data);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

int ping_init(struct task_handle *data) {
    socklen_t saddr_len = sizeof(data->data.ping.saddr);

    data->data.ping.sock_eph = socket_open_tcp(data->opts);
    switch (data->data.ping.sock_eph) {
    default:
        break;
    case -2:
        data->flags.cancelled = 1;
        /* FALLTHRU */
    case -1:
        sys_error(data->error, "opening ephemeral socket", "");
        data->data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        data->flags.done = 1;
        return (1);
    }
    if (getsockname(data->data.ping.sock_tcp,
                    (struct sockaddr *)&data->data.ping.saddr, &saddr_len)) {
        sys_error(data->error, "retrieving socket name", "");
        data->data.ping.rslt->reason.type = REASON_ERROR;
        data->flags.error = 1;
        data->flags.done = 1;
        data->flags.cancelled = 1;
        return (-1);
    }
    return (0);
}

int ping_packet_send(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_packet_rcv(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_packet_timeout(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_release(struct task_handle *data) {
    if (data->data.ping.sock_eph)
        close(data->data.ping.sock_eph);
    if (data->data.ping.sock_icmp)
        close(data->data.ping.sock_icmp);
    if (data->data.ping.sock_tcp)
        close(data->data.ping.sock_tcp);
    return (0);
}