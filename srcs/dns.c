#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <memory.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <nmap.h>
#include <string.h>

/*
DNS SCAN
Abstraction to simply resolve peer ip address from given hostname, also perform
reverse dns resolution on resolved address.
 */

static bool is_valid_ipv4(const char *hostname) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, hostname, &(sa.sin_addr));
    return (result != 0);
}

static void dns_error(struct nmap_error **error_ptr, const char *func_fail,
                      const char *detail) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_DNS;
    strlcpy(error->u.dns.func_fail, func_fail, sizeof(error->u.dns.func_fail));
    strlcpy(error->u.dns.description, detail, sizeof(error->u.dns.description));
    error->error = errno;
}

static int get_ip_name(struct sockaddr_in *addr, char **rslt,
                       struct nmap_error **error_ptr) {
    int ret;
    *rslt = calloc(128, 1);
    ret = getnameinfo((struct sockaddr *)addr, sizeof(*addr), *rslt, 128, NULL,
                      0, 0);
    if (ret) {
        dns_error(error_ptr, "getnameinfo", gai_strerror(ret));
        free(*rslt);
        *rslt = NULL;
        return (1);
    }
    return (0);
}

static int fill_addr_info(const char *hostname, struct sockaddr_in *rslt,
                          struct nmap_error **error_ptr) {
    int ret;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = 0,
        .ai_flags =
            AI_CANONNAME | (is_valid_ipv4(hostname) ? AI_NUMERICHOST : 0),
        .ai_protocol = IPPROTO_IP,
    };
    struct addrinfo *res;
    ret = getaddrinfo(hostname, NULL, &hints, &res);
    if (ret != 0) {
        dns_error(error_ptr, "getaddrinfo", gai_strerror(ret));
        return (1);
    }
    *rslt = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return (0);
}

int dns_init(struct task_handle *data) {
    if (fill_addr_info(data->data.dns.hostname, &data->data.dns.addr,
                       data->error)) {
        data->flags.done = 1;
        data->flags.error = 1;
        return (1);
    }
    if (data->data.dns.dont_resolve == false)
        get_ip_name(&data->data.dns.addr, &data->data.dns.hostname_rslv,
                    data->error);
    data->flags.done = 1;
    return (0);
}
