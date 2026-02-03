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

int socket_open_eph(t_options *opts, int protocol) {
    (void)opts;
    int fd;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = 0};

    fd = socket(AF_INET, SOCK_STREAM, protocol);
    if (fd < 0)
        return (fd);
    if (bind(fd, (const struct sockaddr *)&addr,
             (socklen_t)sizeof(struct sockaddr_in))) {
        close(fd);
        return (-1);
    }
    return (fd);
}

/// @brief
/// @param opts
/// @return ```-1``` if socket() error, else ```-2``` if option error
int socket_open_tcp(t_options *opts) {
    const char *interface = opts->interface;
    struct sockaddr_in addr = {.sin_addr = {.s_addr = INADDR_ANY},
                               .sin_family = AF_INET,
                               .sin_port = opts->src_port};
    int fd;
    int opt;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (fd < 0)
        return (fd);
    if (bind(fd, (const struct sockaddr *)&addr,
             (socklen_t)sizeof(struct sockaddr_in))) {
        close(fd);
        return (-1);
    }
    opt = opts->usurp.arg != NULL;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt))) {
        close(fd);
        return (-1);
    }
    opt = opts->ttl ? opts->ttl : 64;
    if (setsockopt(fd, IPPROTO_IP, IP_TTL, &opt, sizeof(opt))) {
        close(fd);
        return (-1);
    }
    opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &opt, sizeof(opt))) {
        close(fd);
        return (-1);
    }
    if (interface) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface,
                       strlen(interface))) {
            close(fd);
            return (-1);
        }
    }
    return (fd);
}