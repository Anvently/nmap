#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <nmap.h>
#include <protocol.h>

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
void calc_udp_checksum(struct udphdr *hdr, size_t udp_len);

static uint8_t char_to_hex(char c) {
    if (c >= '0' && c <= '9')
        return (c - '0');
    return (10 + (ft_tolower(c) - 'a'));
}

void fill_pattern(const char *pattern, char *data, unsigned int len) {
    unsigned int pattern_len = ft_strlen(pattern);
    unsigned int pattern_idx = 0;
    uint8_t byte;
    if (pattern_len == 0)
        return;
    while (len-- > 0) {
        if (pattern_idx >= pattern_len)
            pattern_idx = 0;
        if (pattern_len - pattern_idx == 1)
            byte = char_to_hex((unsigned char)pattern[pattern_idx]);
        else
            byte = (char_to_hex((unsigned char)pattern[pattern_idx]) << 4) |
                   char_to_hex((unsigned char)pattern[pattern_idx + 1]);
        *data++ = byte;
        pattern_idx += 2;
    }
}

static uint32_t checksum_add(uint32_t sum, const char *buffer, size_t len) {

    for (unsigned int i = 0; i < len - 1; i += 2) {
        sum += *(uint16_t *)(buffer + i);
    }
    if (len % 2 == 1) {
        uint16_t word = (uint16_t)buffer[len - 1] << 8;
        sum += word;
    }
    return sum;
}

static uint16_t calc_checksum(const char *buffer, unsigned int len) {
    uint32_t sum = 0x00;

    for (unsigned int i = 0; i < len - 1; i += 2) {
        sum += *(uint16_t *)(buffer + i);
    }
    if (len % 2 == 1) {
        uint16_t word = (uint16_t)buffer[len - 1] << 8;
        sum += word;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xFFFF);
}

void icmp_ping_format(char *packet, unsigned int len, uint16_t id,
                      uint16_t sequence, t_options *opts) {
    struct icmphdr *hdr = (struct icmphdr *)packet;
    const unsigned int data_size = len - sizeof(struct icmphdr);

    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->un.echo.id = htons(id);
    hdr->un.echo.sequence = htons(sequence);

    if (data_size > 0)
        fill_pattern(opts->pattern, packet + sizeof(struct icmphdr), data_size);
    hdr->checksum = calc_checksum((const char *)packet, len);
}

void init_iphdr(struct iphdr *hdr, size_t total_len, int protocol,
                t_options *opts) {
    switch (protocol) {
    case IPPROTO_ICMP:
        *hdr = (struct iphdr){
            .ihl = 5,
            .version = 4,
            .tos = 0,                    // protocol dependent
            .tot_len = htons(total_len), // protocol dependent
            .id = htons((uint16_t)(rand() % UINT16_MAX)),
            .frag_off = htons(IP_DF), // Dont fragment on
            .ttl = opts->ttl,
            .protocol = IPPROTO_ICMP, // protocol dependent
            .check = 0,               // packet dependent
            .daddr = 0,               // user responsability
            .saddr = 0                // user responsability
        };
        break;
        break;

    case IPPROTO_TCP:
        *hdr = (struct iphdr){
            .ihl = 5,
            .version = 4,
            .tos = 0,                    // protocol dependent
            .tot_len = htons(total_len), // protocol dependent
            .id = htons((uint16_t)(rand() % UINT16_MAX)),
            .frag_off = htons(IP_DF), // Dont fragment on
            .ttl = opts->ttl,
            .protocol = IPPROTO_TCP, // protocol dependent
            .check = 0,              // packet dependent
            .daddr = 0,              // user responsability
            .saddr = 0               // user responsability
        };
        break;

    case IPPROTO_UDP:
        *hdr = (struct iphdr){
            .ihl = 5,
            .version = 4,
            .tos = 0,                    // protocol dependent
            .tot_len = htons(total_len), // protocol dependent
            .id = htons((uint16_t)(rand() % UINT16_MAX)),
            .frag_off = htons(IP_DF), // Dont fragment on
            .ttl = opts->ttl,
            .protocol = IPPROTO_UDP, // protocol dependent
            .check = 0,              // packet dependent
            .daddr = 0,              // user responsability
            .saddr = 0               // user responsability
        };
        break;

    default:
        error(1, errno, "unsupported protocol");
        break;
    }
}

void init_tcphdr(struct tcphdr *hdr, struct tcp_params data) {
    *hdr = (struct tcphdr){
        .th_sport = htons(data.sport),
        .th_dport = htons(data.dport),
        .th_seq =
            data.seq
                ? htons(data.seq)
                : htons((uint16_t)(rand() % UINT16_MAX)), // packet dependent
        .th_ack = data.ack ? htons(data.ack) : 0,         // packet dependent
        .th_off = (uint8_t)(data.tcp_len / sizeof(uint32_t)),
        .th_flags = data.flags, // packet dependent
        .th_win = htons(1024),  // size of receive buffer
        .th_sum = 0,            // packet dependent
        .th_urp = 0,
    };
}

void init_icmphdr(struct icmphdr *hdr, uint8_t type, uint16_t id,
                  uint16_t seq) {
    switch (type) {
    case ICMP_ECHO:
        *hdr = (struct icmphdr){.type = ICMP_ECHO,
                                .code = 0,
                                .checksum = 0,
                                .un.echo.id = htons(id),
                                .un.echo.sequence = htons(seq)};
        break;
    default:
        *hdr = (struct icmphdr){.type = type, .code = 0, .checksum = 0};
        break;
    }
}

void calc_icmp_checksum(struct icmphdr *hdr, size_t icmp_len) {
    hdr->checksum = 0;
    hdr->checksum = calc_checksum((char *)hdr, icmp_len);
}

void calc_tcp_checksum(struct tcphdr *tcp, struct pseudo_iphdr *ph) {
    uint32_t sum = 0;

    tcp->th_sum = 0;

    sum = checksum_add(sum, (const char *)ph, sizeof(*ph));
    sum = checksum_add(sum, (const char *)tcp, ntohs(ph->tcp_len));

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    tcp->th_sum = (uint16_t)~sum;
}

void calc_ip_checksum(struct iphdr *hdr) {
    hdr->check = 0;
    hdr->check = calc_checksum((char *)hdr, sizeof(struct iphdr));
}

void calc_udp_checksum(struct udphdr *hdr, size_t udp_len) {
    hdr->check = 0;
    hdr->check = calc_checksum((char *)hdr, udp_len);
}

/// @brief Compute iphdr + tcphdr checksum, pseudo_iphdr is filled based on
/// iphdr
/// @param buffer
/// @param total_len
void calc_tcp_sum_pkt(char *buffer, size_t total_len) {
    struct iphdr *iphdr = (struct iphdr *)buffer;
    struct tcphdr *tcphdr = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    calc_tcp_checksum(tcphdr,
                      &(struct pseudo_iphdr){
                          .tcp_len = htons(total_len - sizeof(struct iphdr)),
                          .saddr = iphdr->saddr,
                          .daddr = iphdr->daddr,
                          .protocol = IPPROTO_TCP,
                          .reserved = 0});
    calc_ip_checksum(iphdr);
}

void calc_icmp_sum_pkt(char *buffer, size_t total_len) {
    struct iphdr *iphdr = (struct iphdr *)buffer;
    struct icmphdr *icmphdr = (struct icmphdr *)(buffer + sizeof(struct iphdr));

    calc_icmp_checksum(icmphdr, total_len - sizeof(struct iphdr));
    calc_ip_checksum(iphdr);
}

void calc_udp_sum_pkt(char *buffer, size_t total_len) {
    struct iphdr *iphdr = (struct iphdr *)buffer;
    struct udphdr *udphdr = (struct udphdr *)(buffer + sizeof(struct iphdr));

    calc_udp_checksum(udphdr, total_len - sizeof(struct iphdr));
    calc_ip_checksum(iphdr);
}