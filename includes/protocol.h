#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <nmap.h>

#ifndef PROTOCOL_H
#define PROTOCOL_H

struct packet {
    size_t len;
    struct timeval stamp;
    union {
        struct {
            struct iphdr iphdr;
            union {
                struct {
                    struct tcphdr tcphdr;
                    char payload[];
                } tcp;
                struct {
                    struct udphdr udphdr;
                    char payload[];
                } udp;
                struct {
                    struct icmphdr icmphdr;
                    char payload[];
                } icmp;
                struct {
                    struct icmphdr icmphdr;
                    struct iphdr org_iphdr;
                    char payload[];
                } icmp_error;
            };
        };
        char raw[1024];
    } buffer;
};

struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t len;
} __attribute__((packed));

struct tcp_params {
    size_t tcp_len;
    uint8_t flags;
    uint16_t sport;
    uint16_t dport;
    tcp_seq seq; // If 0, random assigned
    tcp_seq ack;
};

void fill_pattern(const char *pattern, char *data, unsigned int len);
void init_iphdr(struct iphdr *hdr, size_t total_len, int protocol,
                t_options *opts);
void init_tcphdr(struct tcphdr *hdr, struct tcp_params data);
void init_icmphdr(struct icmphdr *hdr, uint8_t type, uint16_t id, uint16_t seq);
void calc_tcp_sum_pkt(char *buffer, size_t total_len);
void calc_icmp_sum_pkt(char *buffer, size_t total_len);
void calc_udp_sum_pkt(char *buffer, size_t total_len);
void calc_icmp_checksum(struct icmphdr *hdr, size_t icmp_len);
void calc_tcp_checksum(struct tcphdr *tcp, struct pseudo_iphdr *ph);
void calc_ip_checksum(struct iphdr *hdr);
void calc_udp_checksum(struct udphdr *udp, struct pseudo_iphdr *ph);

void print_verbose_ip(struct iphdr *iphdr, unsigned int padding);
void print_verbose_icmp(struct icmphdr *icmp_hdr, size_t size,
                        unsigned int padding);
void print_verbose_tcp(struct tcphdr *tcphdr, unsigned int padding);
void print_verbose_udp(struct tcphdr *udphdr, unsigned int padding);
void print_verbose_pseudo_iphdr(struct pseudo_iphdr *iphdr);
void print_verbose_packet(const char *buffer, size_t len);
void print_packet_short(const char *buffer, const char *hdr);

ssize_t rcv_packet_msg(int fd, struct packet *packet, struct iovec *iovec,
                       int flags);

#endif