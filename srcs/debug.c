#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

void print_verbose_packet(const char *buffer, unsigned int size) {
    struct iphdr *iphdr = (struct iphdr *)(buffer + sizeof(struct icmphdr) +
                                           sizeof(struct iphdr));
    struct icmphdr *icmp_hdr =
        (struct icmphdr *)((char *)iphdr + sizeof(struct iphdr));
    printf("IP Hdr Dump:\n");
    for (unsigned int i = 0; i < sizeof(struct iphdr); i += 2)
        printf(" %04x", htons(*((uint16_t *)((char *)iphdr + i))));
    printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src	Dst	Data\n"
           " %hhx  %hhx  %02hhx %04hx %04hx   %hhx %04hx  %02hhx  %02hhx %04hx "
           "%-11s",
           (uint8_t)iphdr->version, (uint8_t)iphdr->ihl, iphdr->tos,
           htons(iphdr->tot_len), htons(iphdr->id),
           (htons(iphdr->frag_off) & (0b111 << 13)) >> 13,
           htons(iphdr->frag_off) & ~(0b111 << 13), iphdr->ttl, iphdr->protocol,
           htons(iphdr->check),
           inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}));
    printf(" %s\n", inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}));
    printf(
        "ICMP: type %hhu, code %hhu, size %hu, id 0x%04hx, seq 0x%04hx\n",
        icmp_hdr->type, icmp_hdr->code,
        (uint16_t)(size - (sizeof(struct icmphdr) + 2 * sizeof(struct iphdr))),
        htons(icmp_hdr->un.echo.id), htons(icmp_hdr->un.echo.sequence));
    (void)size;
}