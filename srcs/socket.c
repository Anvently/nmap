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
int socket_open_eph(t_options *opts, int protocol, uint16_t *port) {
    (void)opts;
    int fd;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = 0};
    socklen_t addr_len = sizeof(addr);

    fd = socket(AF_INET, SOCK_STREAM, protocol);
    if (fd < 0)
        return (-1);
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

/// @brief Open RAW TCP socket, binded to local address and connected to remote
/// address. Also set sock options
/// @param opts
/// @param daddr destination address uf for the connect() call
/// @param saddr if provided, socket address will be read and assigned to
/// ```saddr```
/// @return ```-1``` if socket() error, else ```-2``` if other error
int socket_open_tcp(t_options *opts, struct in_addr daddr,
                    struct in_addr *saddr) {
    const char *interface = opts->interface;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = 0};
    socklen_t addr_len = sizeof(addr);
    int fd;
    int opt;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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
    if (saddr) {
        if (getsockname(fd, (struct sockaddr *)&addr, &addr_len)) {
            close(fd);
            return (-2);
        }
        *saddr = addr.sin_addr;
    }
    return (fd);
}