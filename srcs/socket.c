#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <nmap.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

char *get_ip_name(struct sockaddr *addr, bool resolve);
int socket_open_eph(t_options *opts, int sock_type, uint16_t *port);
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr);
int socket_open_udp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr);
int socket_open_icmp(t_options *opts, struct in_addr daddr);

char *get_ip_name(struct sockaddr *addr, bool resolve) {
    static char hostname[128] = {0};
    if (resolve == false) {
        return inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    }
    getnameinfo(addr, sizeof(*addr), hostname, sizeof(hostname), NULL, 0, 0);
    return (hostname);
}

/// @brief Open a SOCK_STREAM sock with given protocol, and put the port
/// assigned by the kernel to ```port```
/// @param opts
/// @param protocol
/// @param port
/// @return ```-1``` if socket() error, else ```-2``` if other error
int socket_open_eph(t_options *opts, int sock_type, uint16_t *port) {
    int fd;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = 0};
    socklen_t addr_len = sizeof(addr);

    fd = socket(AF_INET, sock_type, IPPROTO_IP);
    if (fd < 0)
        return (-1);
    if (opts->interface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, opts->interface,
                       strlen(opts->interface))) {
            close(fd);
            return (-2);
        }
    }
    if (bind(fd, (const struct sockaddr *)&addr,
             (socklen_t)sizeof(struct sockaddr_in))) {
        close(fd);
        return (-2);
    }
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len)) {
        close(fd);
        return (-2);
    }
    *port = addr.sin_port;
    return (fd);
}

static int _socket_open_raw(t_options *opts, struct in_addr daddr,
                            struct in_addr *saddr, int protocol) {
    const char *interface = opts->interface;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = 0};
    socklen_t addr_len = sizeof(addr);
    int fd;
    int opt;

    fd = socket(AF_INET, SOCK_RAW, protocol);
    if (fd < 0)
        return (-1);
    if (interface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface,
                       strlen(interface))) {
            close(fd);
            return (-2);
        }
    }
    if (bind(fd, (const struct sockaddr *)&addr,
             (socklen_t)sizeof(struct sockaddr_in))) {
        close(fd);
        return (-2);
    }
    addr.sin_addr = daddr;
    if (connect(fd, (const struct sockaddr *)&addr,
                (socklen_t)sizeof(struct sockaddr_in))) {
        close(fd);
        return (-2);
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt))) {
        close(fd);
        return (-2);
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &opt, sizeof(opt))) {
        close(fd);
        return (-2);
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &opt, sizeof(opt))) {
        close(fd);
        return (-2);
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt))) {
        close(fd);
        return (-2);
    }
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt))) {
        close(fd);
        return (-2);
    }
    if (saddr) {
        if (getsockname(fd, (struct sockaddr *)&addr, &addr_len)) {
            close(fd);
            return (-2);
        }
        *saddr = addr.sin_addr;
    }
    return (fd);
}

/// @brief Open non-blocking TCP stream socket. Unprivileged operation.
/// @param opts
/// @param daddr
/// @param saddr
/// @return
int socket_open_tcp_connect(t_options *opts) {
    int fd;
    int ttl = opts->ttl;
    const char *interface = opts->interface;
    struct timeval timeout = {.tv_sec = (time_t)(opts->rtt_max / 1000.f)};

    timeout.tv_usec =
        (time_t)((opts->rtt_max - ((float)timeout.tv_sec * 1000.f)) * 1000.f);
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0)
        return (-1);
    if (interface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface,
                       strlen(interface))) {
            close(fd);
            return (-2);
        }
    }
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, (socklen_t)sizeof(ttl))) {
        close(fd);
        return (-2);
    }
    return (fd);
}

/// @brief Open RAW TCP socket, binded to local address and connected to remote
/// address. Also set sock options
/// @param opts
/// @param daddr destination address uf for the connect() call
/// @param saddr if provided, socket address will be read and assigned to
/// ```saddr```
/// @return ```-1``` if socket() error, else ```-2``` if other error
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr) {
    return (_socket_open_raw(opts, daddr, saddr, IPPROTO_TCP));
}

/// @brief Open RAW UDP socket, binded to local address and connected to remote
/// address. Also set sock options
/// @param opts
/// @param daddr destination address uf for the connect() call
/// @param saddr if provided, socket address will be read and assigned to
/// ```saddr```
/// @return ```-1``` if socket() error, else ```-2``` if other error
int socket_open_udp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr) {
    return (_socket_open_raw(opts, daddr, saddr, IPPROTO_UDP));
}

/// @brief Open RAW ICMP socket, binded to local address and connected to remote
/// address. Also set sock options
/// @param opts
/// @param daddr destination address uf for the connect() call
/// @return ```-1``` if socket() error, else ```-2``` if other error
int socket_open_icmp(t_options *opts, struct in_addr daddr) {
    return (_socket_open_raw(opts, daddr, NULL, IPPROTO_ICMP));
}

/// @brief Clear ECONNREFUSED and EHOSTUNREACH error on socket. Occurs if ICMP
/// error received on socket.
/// @param socket
/// @return
int socket_clear_error(int socket) {
    int error;
    socklen_t sval = sizeof(error);

    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &sval))
        return (-1);
    if (error && (error == ECONNREFUSED || error == EHOSTUNREACH)) {
        error = 0;
        if (setsockopt(socket, SOL_SOCKET, SO_ERROR, &error, sval))
            return (-1);
    }
    return (0);
}