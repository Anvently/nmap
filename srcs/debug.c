#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <nmap.h>
#include <string.h>
#include <syscall.h>

struct pseudo_iphdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};

const char *host_state_strings[] = {
    [STATE_DOUBLOON] = "DOUBLOON",
    [STATE_ERROR] = "ERROR",
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
    [SCAN_DNS] = "DNS",   [SCAN_PING] = "PING",    [SCAN_SYN] = "SYN",
    [SCAN_ACK] = "ACK",   [SCAN_NULL] = "NULL",    [SCAN_FIN] = "FIN",
    [SCAN_XMAS] = "XMAS", [SCAN_CONNECT] = "CONN", [SCAN_UDP] = "UDP"};

const char *reason_strings[] = {[REASON_UNKNOWN] = "unknown",
                                [REASON_ICMP_REPLY] = "icmp reply",
                                [REASON_SYN_ACK] = "syn_ack",
                                [REASON_RST] = "reset",
                                [REASON_PORT_UNREACH] = "port unreachable",
                                [REASON_HOST_UNREACH] = "host unreachable",
                                [REASON_UNREACH] = "destination unreachable",
                                [REASON_CONN_REFUSED] = "connection refused",
                                [REASON_USER_INPUT] = "user input",
                                [REASON_NO_RESPONSE] = "no response",
                                [REASON_TIME_EXCEEDED] = "time exceeded",
                                [REASON_ERROR] = "error"};

const char *port_state_strings[] = {[PORT_UNKNOWN] = "unknown",
                                    [PORT_SCANNING] = "scanning",
                                    [PORT_OPENED] = "opened",
                                    [PORT_CLOSED] = "closed",
                                    [PORT_FILTERED] = "filtered",
                                    [PORT_UNFILTERED] = "unfiltered",
                                    [PORT_OPEN_FILTERED] = "opened|filtered",
                                    [PORT_CLOSED_FILTERED] = "closed|filtered",
                                    [PORT_ERROR] = "error"};

static const char *icmp_type_strings[] = {
    [ICMP_ECHOREPLY] = "ECHO REPLY",
    [ICMP_DEST_UNREACH] = "UNREACH",
    [ICMP_SOURCE_QUENCH] = "SOURCE QUENCH",
    [ICMP_REDIRECT] = "REDIRECT",
    [ICMP_ECHO] = "ECHO",
    [ICMP_TIME_EXCEEDED] = "TIME EXCEEDED",
    [ICMP_PARAMPROB] = "PARAM PROB",
    [ICMP_TIMESTAMP] = "TIMESTAMP",
    [ICMP_TIMESTAMPREPLY] = "TIMESTAMP REPLY",
    [ICMP_INFO_REQUEST] = "INFO REQUEST",
    [ICMP_INFO_REPLY] = "INFO REPLY",
    [ICMP_ADDRESS] = "ADDRESS",
    [ICMP_ADDRESSREPLY] = "ADDRESS REPLY"};

void print_worker(struct worker_handle *worker);
void print_task(struct task_handle *task);
void print_host(struct host *);
void print_scan_state(struct scan_result *scan);
void print_verbose_ip(struct iphdr *iphdr, unsigned int padding);
void print_verbose_icmp(struct icmphdr *icmp_hdr, size_t size,
                        unsigned int padding);
void print_verbose_tcp(struct tcphdr *tcphdr, unsigned int padding);
void print_verbose_pseudo_iphdr(struct pseudo_iphdr *iphdr);
void print_verbose_packet(const char *buffer, size_t len);
static void _print_verbose_packet_pad(const char *buffer, size_t len,
                                      unsigned int padding);

void print_packet_short(const char *buffer, const char *hdr);
static void _print_packet_short(const char *buffer, const char *hdr,
                                bool show_tid);

void print_nmap_error(struct nmap_error *error);
static void print_dns_error(struct nmap_error *error);
static void print_sys_error(struct nmap_error *error);
static void print_icmp_error(struct nmap_error *error);
static void print_invalid_packet_error(struct nmap_error *error);

void print_verbose_packet(const char *buffer, size_t len) {
    _print_verbose_packet_pad(buffer, len, 0);
}

void print_nmap_error(struct nmap_error *error) {
    switch (error->type) {
    case NMAP_ERROR_DNS:
        print_dns_error(error);
        break;
    case NMAP_ERROR_SYS:
        print_sys_error(error);
        break;
    case NMAP_ERROR_ICMP:
        print_icmp_error(error);
        break;
    case NMAP_ERROR_WORKER:
        print_sys_error(error);
        break;
    case NMAP_ERROR_INVALID_PACKET:
        print_invalid_packet_error(error);
        break;
    default:
        break;
    }
}

void print_worker(struct worker_handle *worker) {
    size_t nbr_tasks = ft_vector_size(worker->tasks_vec);
    printf("Worker %ld (%hhu), %lu tasks:\n", syscall(SYS_gettid),
           worker->state, nbr_tasks);
    while (nbr_tasks--) {
        print_task(&worker->tasks_vec[nbr_tasks]);
    }
}

void print_task(struct task_handle *task) {
    printf("%s scan for host %s (%s), %2s%2s%2s%2s%2s%2s%2s%2s ",
           scan_type_strings[task->scan_type], task->host->hostname,
           inet_ntoa(task->host->addr.sin_addr),
           task->flags.initialized ? "In" : "",
           task->flags.send_state == 0 ? "Tx" : "Rx",
           task->flags.main_rcv ? "In" : "", task->flags.icmp_rcv ? "IC" : "",
           task->flags.timeout ? "Ti" : "", task->flags.done ? "Do" : "",
           task->flags.error ? "Er" : "", task->flags.cancelled ? "Ca" : "");
    switch (task->scan_type) {
    case SCAN_DNS:

        break;
    case SCAN_PING:
        struct port_info *port = &task->io_data.ping.rslt[0];
        printf("[%hu:%.4s]", port->port, port_state_strings[port->state]);
        break;
    case SCAN_ACK:
    case SCAN_SYN:
    case SCAN_XMAS:
    case SCAN_FIN:
        printf("[");
        for (uint16_t i = 0; i < task->io_data.tcp.nbr_port; i++) {
            struct port_info *port = &task->io_data.tcp.ports[i];
            printf("%hu:%.4s%s", port->port, port_state_strings[port->state],
                   i + 1 == task->io_data.tcp.nbr_port ? "" : ",");
        }
        printf("]");
        break;
    default:
        break;
    }
    if (*task->error) {
        print_nmap_error(*task->error);
    }
    printf("\n");
}

void print_scan_state(struct scan_result *scan) {
    printf("%s (%hhu): %s (%hhu)", scan_type_strings[scan->type], scan->type,
           scan_state_strings[scan->state], scan->state);
    if (scan->type > SCAN_DNS)
        printf(", %hu/%hu port", (scan->nbr_port - scan->remaining),
               scan->nbr_port);
    if (scan->nbr_port < 2 && scan->ports &&
        scan->ports->reason.type != REASON_UNKNOWN)
        printf(", reason = %s (%hhu) (ttl = %hhu)",
               reason_strings[scan->ports->reason.type],
               scan->ports->reason.type, scan->ports->reason.ttl);
    printf("\n");
}

void print_host(struct host *host) {
    if (host->state == STATE_DOUBLOON) {
        printf("Host %s is a duplicated of another host\n---\n",
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
    printf("Current scans : %c%c%c%c%c%c%c%c%c\n",
           host->current_scan.dns ? 'D' : 0, host->current_scan.ping ? 'P' : 0,
           host->current_scan.syn ? 'S' : 0, host->current_scan.ack ? 'A' : 0,
           host->current_scan.null ? 'N' : 0, host->current_scan.fin ? 'F' : 0,
           host->current_scan.xmas ? 'X' : 0,
           host->current_scan.connect ? 'C' : 0,
           host->current_scan.udp ? 'U' : 0);
    for (unsigned int i = 0; i < SCAN_NBR; i++) {
        print_scan_state(host->scans + i);
    }
    printf("---\n");
}

void print_verbose_ip(struct iphdr *iphdr, unsigned int padding) {

    printf("%2$*1$sIP Hdr Dump:\n%2$*1$s", padding, "");
    for (unsigned int i = 0; i < sizeof(struct iphdr); i += 2)
        printf(" %04x", ntohs(*((uint16_t *)((char *)iphdr + i))));
    printf(
        "\n%*sVr HL TOS  Len   ID Flg  off TTL Pro  cks      Src	Dst	Data\n"
        "%*s %hhx  %hhx  %02hhx %04hx %04hx   %hhx %04hx  %02hhx  %02hhx %04hx "
        "%-11s",
        padding, "", padding, "", (uint8_t)iphdr->version, (uint8_t)iphdr->ihl,
        iphdr->tos, ntohs(iphdr->tot_len), ntohs(iphdr->id),
        (ntohs(iphdr->frag_off) & (0b111 << 13)) >> 13,
        ntohs(iphdr->frag_off) & ~(0b111 << 13), iphdr->ttl, iphdr->protocol,
        ntohs(iphdr->check),
        inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}));
    printf(" %s\n", inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}));
}

void print_verbose_icmp(struct icmphdr *icmp_hdr, size_t size,
                        unsigned int padding) {
    struct iphdr *iphdr;

    printf(
        "%*sICMP: type %hhu, code %hhu, size %hu\n", padding, "",
        icmp_hdr->type, icmp_hdr->code,
        (uint16_t)(size - (sizeof(struct icmphdr) + 2 * sizeof(struct iphdr))));
    switch (icmp_hdr->type) {
    case ICMP_ECHO:
        printf("%*sICMP: type %hhu, code %hhu, size %hu, id 0x%04hx, seq "
               "0x%04hx\n",
               padding, "", icmp_hdr->type, icmp_hdr->code,
               (uint16_t)(size -
                          (sizeof(struct icmphdr) + 2 * sizeof(struct iphdr))),
               ntohs(icmp_hdr->un.echo.id), ntohs(icmp_hdr->un.echo.sequence));
        break;
    case ICMP_ECHOREPLY:
    case ICMP_TIMESTAMP:
        return;

    default:
        iphdr = (struct iphdr *)(icmp_hdr + 1);
        printf("%*sOriginal Packet:\n", padding, "");
        _print_verbose_packet_pad((const char *)iphdr,
                                  size - sizeof(struct icmphdr), padding + 2);
        break;
    }
}

void print_verbose_tcp(struct tcphdr *tcphdr, unsigned int padding) {
    printf("%2$*1$sTCP Hdr Dump:\n%2$*1$s", padding, "");
    for (unsigned int i = 0; i < sizeof(struct tcphdr); i += 2)
        printf(" %04x", ntohs(*((uint16_t *)((char *)tcphdr + i))));
    printf("\n%*s  Src   Dst Seq      Ack     off Flags    Win  cks  Urg\n"
           "%*s%5hu %5hu %06x %06x   %hhx  %c%c%c%c%c%c        %04hx %04hx "
           "%04hx\n",
           padding, "", padding, "", ntohs(tcphdr->source), ntohs(tcphdr->dest),
           ntohl(tcphdr->seq), ntohl(tcphdr->ack), tcphdr->th_off,
           tcphdr->fin ? 'F' : 0, tcphdr->syn ? 'S' : 0, tcphdr->rst ? 'R' : 0,
           tcphdr->psh ? 'P' : 0, tcphdr->ack ? 'A' : 0, tcphdr->urg ? 'U' : 0,
           ntohs(tcphdr->window), ntohs(tcphdr->check), ntohs(tcphdr->urg_ptr));
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

static void _print_verbose_packet_pad(const char *buffer, size_t len,
                                      unsigned int padding) {
    print_verbose_ip((struct iphdr *)buffer, padding);
    if (len < sizeof(struct iphdr))
        return;
    if (((struct iphdr *)buffer)->protocol == IPPROTO_TCP) {
        print_verbose_tcp((struct tcphdr *)(buffer + sizeof(struct iphdr)),
                          padding + 2);
    } else if (((struct iphdr *)buffer)->protocol == IPPROTO_ICMP) {
        print_verbose_icmp((struct icmphdr *)(buffer + sizeof(struct iphdr)),
                           len - sizeof(struct iphdr), padding + 2);
    }
}

static void _print_icmp_org_packet(const struct iphdr *iphdr, int padding) {
    const struct tcphdr *tcphdr = (const struct tcphdr *)(iphdr + 1);
    const struct icmphdr *icmphdr = (const struct icmphdr *)(iphdr + 1);
    switch (iphdr->protocol) {
    case IPPROTO_ICMP:
        printf("%*sICMP [%s > ", padding, "",
               inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}));
        printf("%s %s (type=%hhu/code=%hhu)",
               inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}),
               icmp_type_strings[icmphdr->type], icmphdr->type, icmphdr->code);
        switch (icmphdr->type) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            printf(" id=%hu seq=%hu] IP [ttl=%hhu, id=%hu, iplen=%hu]\n",
                   ntohs(icmphdr->un.echo.id), ntohs(icmphdr->un.echo.sequence),
                   iphdr->ttl, ntohs(iphdr->id), ntohs(iphdr->tot_len));
            break;
        default:
            printf("] IP [ttl=%hhu, id=%hu, iplen=%hu]\n", iphdr->ttl,
                   ntohs(iphdr->id), ntohs(iphdr->tot_len));
        }
        break;
    case IPPROTO_TCP:
        printf("%*sTCP %s:%hu > ", padding, "",
               inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}),
               ntohs(tcphdr->th_sport));
        printf("%s:%hu ttl=%hhu id=%hu iplen=%hu seq=%u \n",
               inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}),
               ntohs(tcphdr->th_dport), iphdr->ttl, ntohs(iphdr->id),
               ntohs(iphdr->tot_len), ntohl(tcphdr->seq));
        break;
    default:
        printf("UNSUPPORTED PROTOCOL");
    }
}

void print_packet_short(const char *buffer, const char *hdr) {
    _print_packet_short(buffer, hdr, true);
}

static void _print_packet_short(const char *buffer, const char *hdr,
                                bool show_tid) {
    const struct iphdr *iphdr = (const struct iphdr *)buffer;
    const struct tcphdr *tcphdr =
        (const struct tcphdr *)(buffer + sizeof(*iphdr));
    const struct icmphdr *icmphdr =
        (const struct icmphdr *)(buffer + sizeof(*iphdr));
    int padding;
    if (show_tid)
        padding = printf("[%d] %s ", gettid(), hdr ? hdr : "");
    else if (hdr)
        padding = printf("%s ", hdr);
    switch (iphdr->protocol) {
    case IPPROTO_ICMP:
        printf("ICMP [%s > ",
               inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}));
        printf("%s %s (type=%hhu/code=%hhu)",
               inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}),
               icmp_type_strings[icmphdr->type], icmphdr->type, icmphdr->code);
        switch (icmphdr->type) {
        case ICMP_ECHO:
        case ICMP_ECHOREPLY:
            printf(" id=%hu seq=%hu] IP [ttl=%hhu, id=%hu, iplen=%hu]\n",
                   ntohs(icmphdr->un.echo.id), ntohs(icmphdr->un.echo.sequence),
                   iphdr->ttl, ntohs(iphdr->id), ntohs(iphdr->tot_len));
            break;

        case ICMP_TIMESTAMP:
        case ICMP_TIMESTAMPREPLY:
        case ICMP_INFO_REQUEST:
        case ICMP_INFO_REPLY:
            printf("] IP [ttl=%hhu, id=%hu, iplen=%hu]\n", iphdr->ttl,
                   ntohs(iphdr->id), ntohs(iphdr->tot_len));
            break;
        default:
            printf("] IP [ttl=%hhu, id=%hu, iplen=%hu]\n", iphdr->ttl,
                   ntohs(iphdr->id), ntohs(iphdr->tot_len));
            _print_icmp_org_packet((const struct iphdr *)(icmphdr + 1),
                                   padding);
        }
        break;
    case IPPROTO_TCP:
        printf("TCP %s:%hu > ",
               inet_ntoa((struct in_addr){.s_addr = iphdr->saddr}),
               ntohs(tcphdr->th_sport));
        printf("%s:%hu %c%c%c%c%c%c ttl=%hhu id=%hu iplen=%hu seq=%u win=%hu\n",
               inet_ntoa((struct in_addr){.s_addr = iphdr->daddr}),
               ntohs(tcphdr->th_dport), tcphdr->fin ? 'F' : 0,
               tcphdr->syn ? 'S' : 0, tcphdr->rst ? 'R' : 0,
               tcphdr->psh ? 'P' : 0, tcphdr->ack ? 'A' : 0,
               tcphdr->urg ? 'U' : 0, iphdr->ttl, ntohs(iphdr->id),
               ntohs(iphdr->tot_len), ntohl(tcphdr->seq),
               ntohs(tcphdr->th_win));
        break;
    default:
        printf("UNSUPPORTED PROTOCOL");
    }
}

static void print_dns_error(struct nmap_error *error) {
    printf("%s: %s", error->u.dns.func_fail, error->u.dns.description);
    if (error->error != 0)
        printf(" => %s (%d)", strerror(error->error), error->error);
}
static void print_sys_error(struct nmap_error *error) {
    printf("%s: %s", error->u.sys.func_fail, error->u.sys.description);
    if (error->error != 0)
        printf(" => %s (%d)", strerror(error->error), error->error);
}
static void print_icmp_error(struct nmap_error *error) {
    printf("[ICMP] %s (%hhu) from %s",
           icmp_type_strings[error->u.icmp.icmphdr.type],
           error->u.icmp.icmphdr.type,
           inet_ntoa((struct in_addr){.s_addr = error->u.icmp.iphdr.saddr}));
}
static void print_invalid_packet_error(struct nmap_error *error) {
    printf("%s => ", error->u.packet.context);
    _print_packet_short((const char *)&error->u.packet.iphdr, "", false);
}
