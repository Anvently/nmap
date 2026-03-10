#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <nmap.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>

/*
CONNECT SCAN IMPLEMENTATION

@note: unprivileged scan
@note: use non blocking socket with connect() system call
@note: All probe are sent together
*/

struct connect_context {
    uint16_t nbr_port;  // Count how many port were initialized
    uint16_t remaining; // Count how many port are waiting for a response
    struct timeval send_stamp;
    struct pollfd *pollfds;
};

void nmap_sys_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail);
void nmap_connect_error(struct nmap_error **error_ptr, int err);

int socket_open_tcp_connect(t_options *opts);

int connect_init(struct task_handle *data);

static void resolve_state(struct port_info *port);

float compute_rtt(struct timeval start, struct timeval end);
float timeval_to_ms(struct timeval tv);

static void resolve_state(struct port_info *port) {
    switch (port->reason.type) {
    case REASON_ERROR:
        port->state = PORT_ERROR;
        break;

    case REASON_SYN_ACK:
        port->state = PORT_OPENED;
        break;

    case REASON_UNREACH:
    case REASON_NO_RESPONSE:
    case REASON_HOST_UNREACH:
        port->state = PORT_FILTERED;
        break;

    case REASON_CONN_REFUSED:
        port->state = PORT_CLOSED;
        break;

    default:
        port->state = PORT_UNKNOWN;
        break;
    }
}

static void release_context(struct connect_context *ctx) {
    if (ctx == NULL)
        return;
    if (ctx->pollfds) {
        for (unsigned int i = 0; i < ctx->nbr_port; i++)
            if (ctx->pollfds[i].fd >= 0)
                close(ctx->pollfds[i].fd);
        free(ctx->pollfds);
    }
    free(ctx);
    return;
}

static int init_context(struct task_handle *data) {
    struct connect_context *ctx;
    data->ctx = ctx = calloc(1, sizeof(struct connect_context));
    if (data->ctx == NULL) {
        nmap_sys_error(data->error, "allocating task context", "");
        return (1);
    }
    ctx->pollfds =
        malloc(sizeof(struct pollfd) * data->io_data.connect.nbr_port);
    if (ctx->pollfds == NULL) {
        release_context(ctx);
        nmap_sys_error(data->error, "allocating task context", "");
        return (1);
    }

    for (int i = 0; i < data->io_data.connect.nbr_port; i++) {
        ctx->pollfds[i].fd = socket_open_tcp_connect(data->opts);
        switch (ctx->pollfds[i].fd) {
        default:
            ctx->pollfds[i].events = POLLOUT | POLLERR;
            break;
        case -1: // socket error
            data->flags.cancelled = 1;
            /* FALLTHRU */
        case -2: // sys error
            release_context(ctx);
            nmap_sys_error(data->error, "opening socket for connect scan", "");
            return (1);
        }
        ctx->nbr_port++;
    }
    return (0);
}

static void connect_sockets(struct task_handle *data) {
    struct connect_context *ctx = (struct connect_context *)data->ctx;
    struct sockaddr_in daddr = {.sin_addr = data->io_data.connect.daddr,
                                .sin_family = AF_INET,
                                .sin_port = 0};
    struct port_info *port_info;
    int ret;

    gettimeofday(&ctx->send_stamp, NULL);
    for (unsigned int i = 0; i < ctx->nbr_port; i++) {
        daddr.sin_port = htons(data->io_data.connect.ports[i].port);
        ret = connect(ctx->pollfds[i].fd, (const struct sockaddr *)&daddr,
                      (socklen_t)sizeof(daddr));
        if (ret == 0 || errno == EINPROGRESS) {
            ctx->remaining++;
            errno = 0;
        } else {
            port_info = &data->io_data.connect.ports[i];
            nmap_sys_error(&port_info->error, "connect", "");
            port_info->reason.type = REASON_ERROR;
            resolve_state(port_info);
            close(ctx->pollfds[i].fd);
            ctx->pollfds[i].events = 0;
            ctx->pollfds[i].fd = -1;
        }
    }
}

static void check_port_state(struct pollfd *pollfd, struct port_info *info) {
    int error = 0;
    socklen_t size_error = (socklen_t)sizeof(error);
    struct sockaddr_in peer_addr;
    socklen_t size_addr = sizeof(peer_addr);

    if (getsockopt(pollfd->fd, SOL_SOCKET, SO_ERROR, &error, &size_error)) {
        nmap_sys_error(&info->error, "getsockopt", "using connect() scan port");
        info->reason.type = REASON_ERROR;
        return;
    }
    switch (error) {
    case 0:
        if (getpeername(pollfd->fd, (struct sockaddr *)&peer_addr,
                        &size_addr)) {
            if (errno == ENOTCONN) {
                nmap_connect_error(&info->error, errno);
                info->reason.type = REASON_ERROR;
                errno = 0;
            } else {
                nmap_sys_error(&info->error, "getpeername",
                               "checking for socket connection status");
                info->reason.type = REASON_ERROR;
            }
        } else {
            info->reason.type = REASON_SYN_ACK;
        }
        break;
    case EHOSTUNREACH:
        info->reason.type = REASON_HOST_UNREACH;
        break;
    case ECONNREFUSED:
        info->reason.type = REASON_CONN_REFUSED;
        break;
    case ENETUNREACH:
        info->reason.type = REASON_UNREACH;
        break;
    default:
        nmap_connect_error(&info->error, error);
        info->reason.type = REASON_ERROR;
    }
}

int connect_init(struct task_handle *data) {
    struct connect_context *ctx;
    struct port_info *port;
    struct timeval stamp;
    struct timespec timeout = {.tv_sec = data->base_timeout.tv_sec,
                               .tv_nsec = data->base_timeout.tv_usec * 1000};
    bool timed_out;

    if (init_context(data)) {
        data->flags.error = 1;
        data->flags.done = 1;
        return (1);
    }
    ctx = (struct connect_context *)data->ctx;
    connect_sockets(data); // Do connect() syscalls
    while (ctx->remaining > 0) {
        timed_out = ppoll(ctx->pollfds, ctx->nbr_port, &timeout, NULL) == 0;
        for (unsigned int i = 0; i < ctx->nbr_port; i++) {
            port = &data->io_data.connect.ports[i];
            if (port->state != PORT_SCANNING ||
                (timed_out == false && ctx->pollfds[i].revents == 0))
                continue;
            gettimeofday(&stamp, NULL);
            port->reason.rtt = compute_rtt(ctx->send_stamp, stamp);
            if (timed_out) {
                port->reason.type = REASON_NO_RESPONSE;
            } else {
                check_port_state(&ctx->pollfds[i], port);
            }
            resolve_state(port);
            close(ctx->pollfds[i].fd);
            ctx->pollfds[i].fd = -1;
            ctx->pollfds[i].events = 0;
            ctx->remaining--;
        }
    }
    release_context(ctx);
    data->flags.done = 1;
    return (1);
}
