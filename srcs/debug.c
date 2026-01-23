#include <arpa/inet.h>
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

const char *host_state_strings[] = {
    [STATE_DOUBLOON] = "DOUBLOON",
    [STATE_PENDING_RESOLVE] = "PENDING_RESOLVE",
    [STATE_DOWN] = "DOWN",
    [STATE_RESOLVING] = "RESOLVING",
    [STATE_RESOLVED] = "RESOLVED",
    [STATE_RESOLVE_FAILED] = "RESOLVE_FAILED",
    [STATE_PING_PENDING] = "PING_PENDING",
    [STATE_PING_SENT] = "PING_SENT",
    [STATE_PING_TIMEOUT] = "PING_TIMEOUT",
    [STATE_UP] = "UP",
    [STATE_SCAN_PENDING] = "SCAN_PENDING",
    [STATE_SCAN_RUNNING] = "SCAN_RUNNING",
    [STATE_SCAN_DONE] = "SCAN_DONE",
};

const char *scan_state_strings[] = {[SCAN_DISABLE] = "disabled",
                                    [SCAN_PENDING] = "pending",
                                    [SCAN_RUNNING] = "running",
                                    [SCAN_DONE] = "done"};

const char *scan_type_strings[] = {
    [SCAN_DNS] = "DNS",        [SCAN_PING] = "PING",    [SCAN_SYN] = "SYN",
    [SCAN_ACK] = "ACK",        [SCAN_NULL] = "NULL",    [SCAN_FIN] = "FIN",
    [SCAN_XMAS] = "XMAS",      [SCAN_CONNECT] = "CONN", [SCAN_UDP] = "UDP",
    [SCAN_RAW_UDP] = "UDP_RAW"};

void print_host(struct host *);
void print_verbose_ip(struct iphdr *iphdr);
void print_verbose_icmp(struct icmphdr *icmp_hdr, size_t size);
void print_verbose_tcp(struct tcphdr *tcphdr);
void print_verbose_pseudo_iphdr(struct pseudo_iphdr *iphdr);
void print_verbose_packet(const char *buffer, size_t len);

static void print_scan_state(struct scan_result *scan) {
    printf("%s (%hhu): %s (%hhu)", scan_type_strings[scan->type], scan->type,
           scan_state_strings[scan->state], scan->state);
    if (scan->type > SCAN_DNS)
        printf(", %hu port", scan->nbr_port);
    if (scan->nbr_port < 2 && scan->ports &&
        scan->ports->reason.type != REASON_UNKNOWN)
        printf(", reason = %hhu (ttl = %hhu)", scan->ports->reason.type,
               scan->ports->reason.ttl);
    printf("\n");
}

void print_host(struct host *host) {
    if (host->state == STATE_DOUBLOON) {
        printf("Host %s is a duplicated of another host :\n---\n",
               host->hostname);
        return;
    }
    const char *addr_ipv4 = inet_ntoa(host->addr.sin_addr);

    if (host->state == STATE_PENDING_RESOLVE ||
        host->state == STATE_RESOLVE_FAILED)
        addr_ipv4 = "unkown";
    printf("%s (%s - %s) : %s (%hhu)\n", host->hostname, addr_ipv4,
           host->hostname_rsvl == NULL ? "unkown" : host->hostname_rsvl,
           host_state_strings[host->state], host->state);
    printf(
        "Current scans : %c%c%c%c%c%c%c%c%c%c\n",
        host->current_scan.dns ? 'D' : 0, host->current_scan.ping ? 'P' : 0,
        host->current_scan.syn ? 'S' : 0, host->current_scan.ack ? 'A' : 0,
        host->current_scan.null ? 'N' : 0, host->current_scan.fin ? 'F' : 0,
        host->current_scan.xmas ? 'X' : 0, host->current_scan.connect ? 'C' : 0,
        host->current_scan.udp ? 'U' : 0, host->current_scan.raw_udp ? 'U' : 0);
    for (unsigned int i = 0; i < SCAN_NBR; i++) {
        print_scan_state(host->scans + i);
    }
    if (host->scans[SCAN_RAW_UDP].state > SCAN_DISABLE)
        print_scan_state(&host->scans[SCAN_RAW_UDP]);
    printf("---\n");
}

void print_verbose_ip(struct iphdr *iphdr) {

    printf("IP Hdr Dump:\n");
    for (unsigned int i = 0; i < sizeof(struct iphdr); i += 2)
        printf(" %04x", ntohs(*((uint16_t *)((char *)iphdr + i))));
    printf("\nVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src	Dst	Data\n"
           " %hhx  %hhx  %02hhx %04hx %04hx   %hhx %04hx  %02hhx  %02hhx %04hx "
           "%-11s",
           (uint8_t)iphdr->version, (uint8_t)iphdr->ihl, iphdr->tos,
           ntohs(iphdr->tot_len), ntohs(iphdr->id),
           (ntohs(iphdr->frag_off) & (0b111 << 13)) >> 13,
           ntohs(iphdr->frag_off) & ~(0b111 << 13), iphdr->ttl, iphdr->protocol,
           ntohs(iphdr->check),
           inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}));
    printf(" %s\n", inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}));
}

void print_verbose_icmp(struct icmphdr *icmp_hdr, size_t size) {
    struct iphdr *iphdr;

    printf(
        "ICMP: type %hhu, code %hhu, size %hu\n", icmp_hdr->type,
        icmp_hdr->code,
        (uint16_t)(size - (sizeof(struct icmphdr) + 2 * sizeof(struct iphdr))));
    switch (icmp_hdr->type) {
    case ICMP_ECHO:
        printf(
            "ICMP: type %hhu, code %hhu, size %hu, id 0x%04hx, seq 0x%04hx\n",
            icmp_hdr->type, icmp_hdr->code,
            (uint16_t)(size -
                       (sizeof(struct icmphdr) + 2 * sizeof(struct iphdr))),
            ntohs(icmp_hdr->un.echo.id), ntohs(icmp_hdr->un.echo.sequence));
        break;
    case ICMP_ECHOREPLY:
    case ICMP_TIMESTAMP:
        return;

    default:
        iphdr = (struct iphdr *)(icmp_hdr + 1);
        printf("Original Packet:\n");
        print_verbose_packet((const char *)iphdr,
                             size - sizeof(struct icmphdr));
        break;
    }
}

void print_verbose_tcp(struct tcphdr *tcphdr) {
    printf("TCP Hdr Dump:\n");
    for (unsigned int i = 0; i < sizeof(struct tcphdr); i += 2)
        printf(" %04x", ntohs(*((uint16_t *)((char *)tcphdr + i))));
    printf(
        "\n  Src   Dst Seq      Ack     off Flags    Win  cks  Urg\n"
        "%5hu %5hu %06x %06x   %hhx  %c%c%c%c%c%c        %04hx %04hx %04hx\n",
        ntohs(tcphdr->source), ntohs(tcphdr->dest), ntohl(tcphdr->seq),
        ntohl(tcphdr->ack), tcphdr->th_off, tcphdr->fin ? 'F' : 0,
        tcphdr->syn ? 'S' : 0, tcphdr->rst ? 'R' : 0, tcphdr->psh ? 'P' : 0,
        tcphdr->ack ? 'A' : 0, tcphdr->urg ? 'U' : 0, ntohs(tcphdr->window),
        ntohs(tcphdr->check), ntohs(tcphdr->urg_ptr));
}

void print_verbose_pseudo_iphdr(struct pseudo_iphdr *iphdr) {
    struct in_addr saddr = {.s_addr = iphdr->saddr};
    struct in_addr daddr = {.s_addr = iphdr->daddr};
    printf("Pseudo-IP Hdr Dump:\n");
    for (unsigned int i = 0; i < sizeof(struct pseudo_iphdr); i += 2)
        printf(" %04x", ntohs(*((uint16_t *)((char *)iphdr + i))));
    printf("\nSrc           Dest           Pro  TCP-len\n%-13s ",
           inet_ntoa(saddr));
    printf("%13s %02hhx   %04hx\n", inet_ntoa(daddr), iphdr->protocol,
           ntohs(iphdr->tcp_len));
}

void print_verbose_packet(const char *buffer, size_t len) {
    print_verbose_ip((struct iphdr *)buffer);
    if (len < sizeof(struct iphdr))
        return;
    if (((struct iphdr *)buffer)->protocol == IPPROTO_TCP) {
        print_verbose_tcp((struct tcphdr *)(buffer + sizeof(struct iphdr *)));
    } else if (((struct iphdr *)buffer)->protocol == IPPROTO_ICMP) {
        print_verbose_icmp((struct icmphdr *)(buffer + sizeof(struct iphdr *)),
                           len - sizeof(struct iphdr));
    }
}
