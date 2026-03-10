#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <linux/errqueue.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <nmap.h>
#include <protocol.h>
#include <sys/socket.h>

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
    sum = checksum_add(sum, (const char *)tcp, ntohs(ph->len));

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    tcp->th_sum = (uint16_t)~sum;
}

void calc_udp_checksum(struct udphdr *udp, struct pseudo_iphdr *ph) {
    uint32_t sum = 0;

    udp->uh_sum = 0;

    sum = checksum_add(sum, (const char *)ph, sizeof(*ph));
    sum = checksum_add(sum, (const char *)udp, ntohs(ph->len));

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    udp->uh_sum = (uint16_t)~sum;
}

void calc_ip_checksum(struct iphdr *hdr) {
    hdr->check = 0;
    hdr->check = calc_checksum((char *)hdr, sizeof(struct iphdr));
}

/// @brief Compute iphdr + tcphdr checksum, pseudo_iphdr is filled based on
/// iphdr
/// @param buffer
/// @param total_len
void calc_tcp_sum_pkt(char *buffer, size_t total_len) {
    struct iphdr *iphdr = (struct iphdr *)buffer;
    struct tcphdr *tcphdr = (struct tcphdr *)(buffer + sizeof(struct iphdr));

    calc_tcp_checksum(
        tcphdr,
        &(struct pseudo_iphdr){.len = htons(total_len - sizeof(struct iphdr)),
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

    calc_udp_checksum(
        udphdr,
        &(struct pseudo_iphdr){.len = htons(total_len - sizeof(struct iphdr)),
                               .saddr = iphdr->saddr,
                               .daddr = iphdr->daddr,
                               .protocol = IPPROTO_UDP,
                               .reserved = 0});
    calc_ip_checksum(iphdr);
}

/// @brief Read an incoming packet and its ancilliary data using
/// ```recvmsg()```. The packet is timestamped with ```SO_TIMESTAMP``` control
/// message, and ttl is filled with ```IP_TTL``` control message. If
/// ```RECV_ERR``` control message is received, icmp error is reconstructed in
/// ```packet->buffer.icmp_error```.
/// @param fd
/// @param pkt
/// @param iovec vector of buffer to which incoming packet will be assigned.
/// @note for icmp error, full icmp packet is only reconstructed in ```packet```
/// structure, the given vector will only contain the beginning of the packet
/// that caused the error.
/// @param flags flags passed to ```recv_msg``` call
/// @return ```-1``` if error or number of len of total reconstructed packet
ssize_t rcv_packet_msg(int fd, struct packet *pkt, struct iovec *iovec,
                       int flags) {
    char ancilliary[512];
    struct sock_extended_err *err;
    struct msghdr mhdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = iovec, // will contain origin packet
        .msg_iovlen = 1,
        .msg_control = &ancilliary[0],
        .msg_controllen = sizeof(ancilliary),
        .msg_flags =
            0}; // Expect : MSG_TRUNC (ctx buff too small), MSG_CTRUNC (extra
                // too small), MSG_ERRQUEUE (something to read in ERR queue)
    ssize_t ret;

    bzero(&pkt->stamp, sizeof(struct timeval));
    ret = recvmsg(fd, &mhdr, flags);
    if (ret <= 0)
        return (ret);

    if (mhdr.msg_flags & MSG_TRUNC || mhdr.msg_flags & MSG_CTRUNC) {
        fprintf(stderr, "Error : buffer size too small: %s %s\n",
                mhdr.msg_flags & MSG_TRUNC ? "MSG_TRUNC" : "",
                mhdr.msg_flags & MSG_CTRUNC ? "MSG_CTRUNC" : "");
        return (-1);
    }

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
        switch (cmsg->cmsg_level) {
        case SOL_SOCKET:
            switch (cmsg->cmsg_type) {
            case SCM_TIMESTAMP:
                memcpy(&pkt->stamp, CMSG_DATA(cmsg), sizeof(struct timeval));
                break;
            default:
                fprintf(
                    stderr,
                    "Error : received unknow control message of level = %d,  "
                    "type = %d\n",
                    cmsg->cmsg_level, cmsg->cmsg_type);
                return (-1);
            }
            break;

        case IPPROTO_IP:
            switch (cmsg->cmsg_type) {
            case IP_ORIGDSTADDR:
                pkt->buffer.iphdr.daddr =
                    ((struct sockaddr_in *)CMSG_DATA(cmsg))->sin_addr.s_addr;
                break;
            case IP_TTL:
                pkt->buffer.iphdr.ttl = (uint8_t)(*(uint32_t *)CMSG_DATA(cmsg));
                break;
            case IP_RECVERR:
                err = (struct sock_extended_err *)CMSG_DATA(cmsg);
                if (err->ee_origin != SO_EE_ORIGIN_ICMP) {
                    printf("Error : invalid err msg origin of %u \n",
                           err->ee_origin);
                    return (-1);
                }
                pkt->buffer.iphdr.protocol = IPPROTO_ICMP;
                pkt->buffer.iphdr.saddr =
                    ((struct sockaddr_in *)SO_EE_OFFENDER(err))
                        ->sin_addr.s_addr;
                pkt->buffer.iphdr.tot_len =
                    htons(ret + sizeof(struct iphdr) + sizeof(struct icmphdr));
                pkt->buffer.iphdr.check = 0;
                pkt->buffer.iphdr.id = 0;
                pkt->buffer.icmp_error.icmphdr =
                    (struct icmphdr){.checksum = 0,
                                     .type = err->ee_type,
                                     .code = err->ee_code,
                                     .un.gateway = htonl(err->ee_info)};
                break;
            default:
                fprintf(
                    stderr,
                    "Error : received unknow control message of level = %d,  "
                    "type = %d\n",
                    cmsg->cmsg_level, cmsg->cmsg_type);
                return (-1);
            }

            break;

        default:
            fprintf(stderr,
                    "Error : received unknow control message of level = %d,  "
                    "type = %d\n",
                    cmsg->cmsg_level, cmsg->cmsg_type);
            return (-1);
        }
    }
    return ((ssize_t)ntohs(pkt->buffer.iphdr.tot_len));
}
