#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <error.h>
#include <ft_nmap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>

void error_unknown_host(const char *hostname);
void error_default(const char *hostname);

int fill_addr_info(const char *hostname, struct addrinfo **rslt,
                   t_options *opts) {
    (void)opts;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_RAW,
        .ai_flags = AI_CANONNAME,
        .ai_protocol = IPPROTO_ICMP,
    };
    switch (getaddrinfo(hostname, NULL, &hints, rslt)) {
    case 0:
        break;
    case EAI_NONAME:
        error_unknown_host(hostname);
        return (1);
    default:
        error_default(hostname);
        return (1);
    }
    return (0);
}

int register_socket(t_options *opts) {
    (void)opts;
    // struct timeval timeout = {0};
    int fd = -1;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0)
        error(1, errno, "opening socket");
    if (opts->tos > 0) {
        if (setsockopt(fd, IPPROTO_IP, IP_TOS, &opts->tos, sizeof(opts->tos)) !=
            0)
            error(1, errno, "setting socket tos");
    }
    if (opts->ttl > 0) {
        if (setsockopt(fd, IPPROTO_IP, IP_TTL, &opts->ttl, sizeof(opts->ttl)) !=
            0)
            error(1, errno, "setting socket ttl");
    }
    // if (opts->linger_timeout > 0) {
    //     timeout.tv_sec = opts->linger_timeout;
    //     if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
    //                    sizeof(timeout)) != 0)
    //         error(1, errno, "setting socket timeout");
    // }

    return (fd);
}

char *get_ip_name(struct sockaddr *addr, bool resolve) {
    static char hostname[128] = {0};
    if (resolve == false) {
        return inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
    }
    getnameinfo(addr, sizeof(*addr), hostname, sizeof(hostname), NULL, 0, 0);
    return (hostname);
}