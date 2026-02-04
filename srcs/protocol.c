#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <nmap.h>

struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};

static uint8_t char_to_hex(char c) {
    if (c >= '0' && c <= '9')
        return (c - '0');
    return (10 + (ft_tolower(c) - 'a'));
}

static void fill_pattern(const char *pattern, unsigned char *data,
                         unsigned int len) {

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

void tcp_format(char *packet, unsigned int len, uint16_t src_port,
                uint16_t dest_port, t_options *opts, uint16_t flags) {
    struct tcphdr *hdr =
        (struct tcphdr *)(packet + sizeof(struct pseudo_iphdr));
    const unsigned int data_size = len - sizeof(struct tcphdr);
    unsigned char c = '0';

    ft_bzero(hdr, sizeof(struct tcphdr));
    hdr->th_sport = htons(src_port);
    hdr->th_dport = htons(dest_port);
    hdr->th_seq = htonl((uint32_t)rand());
    hdr->th_off = (uint8_t)(sizeof(struct tcphdr) / sizeof(uint32_t));
    hdr->th_flags = TH_SYN;
    hdr->th_win = htons(4096 - sizeof(struct iphdr));

    hdr->th_sum = calc_checksum((const char *)packet, len);
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
