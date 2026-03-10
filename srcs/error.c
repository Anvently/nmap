#include <errno.h>
#include <error.h>
#include <nmap.h>
#include <protocol.h>

void nmap_sys_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail);
void nmap_icmp_error(struct nmap_error **error_ptr, struct packet *packet);
void nmap_packet_error(struct nmap_error **error_ptr, const char *context,
                       struct packet *packet);
void nmap_dns_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail);
void nmap_connect_error(struct nmap_error **error_ptr, int err);

void nmap_sys_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_SYS;
    ft_strlcpy(error->u.sys.func_fail, func_fail,
               sizeof(error->u.dns.func_fail));
    ft_strlcpy(error->u.sys.description, detail,
               sizeof(error->u.dns.description));
    error->error = errno;
}

void nmap_icmp_error(struct nmap_error **error_ptr, struct packet *packet) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_ICMP;
    error->error = 0;
    error->u.icmp.iphdr = packet->buffer.iphdr;
    error->u.icmp.icmphdr = packet->buffer.icmp.icmphdr;
    if (packet->len >= 2 * sizeof(struct iphdr) + sizeof(struct icmphdr))
        error->u.icmp.org_iphdr = *(struct iphdr *)&packet->buffer.icmp.payload;
    if (packet->len >= 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8)
        memcpy(&error->u.icmp.detail,
               packet->buffer.icmp.payload + sizeof(struct iphdr), 8);
}

void nmap_packet_error(struct nmap_error **error_ptr, const char *context,
                       struct packet *packet) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_INVALID_PACKET;
    ft_strlcpy(error->u.packet.context, context,
               sizeof(error->u.packet.context));
    memcpy(&error->u.packet.iphdr, packet->buffer.raw,
           sizeof(error->u) - sizeof(error->u.packet.context));
    error->error = 0;
}

void nmap_dns_error(struct nmap_error **error_ptr, const char *func_fail,
                    const char *detail) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_DNS;
    ft_strlcpy(error->u.dns.func_fail, func_fail,
               sizeof(error->u.dns.func_fail));
    ft_strlcpy(error->u.dns.description, detail,
               sizeof(error->u.dns.description));
    error->error = errno;
}

void nmap_connect_error(struct nmap_error **error_ptr, int err) {
    struct nmap_error *error;
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = NMAP_ERROR_CONNECT;
    error->u.connect.error = err;
    error->error = errno;
}