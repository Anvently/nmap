#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <netinet/ip.h>
#include <nmap.h>

extern const char *reason_strings[12];
extern const char *host_state_strings[14];
extern const char *scan_type_strings[11];
extern const char *port_state_strings[9];

void print_nmap_error(struct nmap_error *error);
void print_task(struct task_handle *task);
void print_task_result(struct task_handle *task) {
    int tid = gettid();
    if (getpid() != tid)
        printf("[%d] ", tid);
    printf("%s%s%s: ",
           (task->flags.cancelled
                ? TERM_CL_RED
                : (task->flags.error ? TERM_CL_YELLOW : TERM_CL_GREEN)),
           (task->flags.cancelled ? "cancelled"
                                  : (task->flags.error ? "error" : "success")),
           TERM_CL_RESET);
    switch (task->scan_type) {
    case SCAN_DNS:
        printf("DNS resolution for host %s: ", task->host->hostname);
        if (task->flags.cancelled == 0) {
            printf("%s (%s)", inet_ntoa(task->io_data.dns.addr.sin_addr),
                   task->io_data.dns.hostname_rslv
                       ? task->io_data.dns.hostname_rslv
                       : "");
        }
        if (*task->error) {
            printf(", ");
            print_nmap_error(*task->error);
        }
        break;
    case SCAN_PING:
        printf("PING result for host %s:", task->host->hostname);
        if (task->io_data.ping.rslt->retries > 0)
            printf(" retry %hhu", task->io_data.ping.rslt->retries);
        printf(" %s (%hhu, %.2f)",
               reason_strings[task->io_data.ping.rslt->reason.type],
               task->io_data.ping.rslt->reason.ttl,
               task->io_data.ping.rslt->reason.rtt);
        if (*task->error) {
            printf(", ");
            print_nmap_error(*task->error);
        }
        break;
    default:
        if (task->scan_type >= SCAN_SYN && task->scan_type <= SCAN_XMAS) {
            printf("%s scan result for host %s (%hu ports): ",
                   scan_type_strings[task->scan_type], task->host->hostname,
                   task->io_data.tcp.nbr_port);
            for (uint16_t i = 0; i < task->io_data.tcp.nbr_port; i++) {
                printf("%hu (%s), ", task->io_data.tcp.ports[i].port,
                       port_state_strings[task->io_data.tcp.ports[i].state]);
            }
        }
        if (*task->error) {
            printf("=> ");
            print_nmap_error(*task->error);
        }
        break;
    }
    printf("\n");
}

const char *retrieve_service_name(enum scan_type type, uint16_t port,
                                  struct service *vec_services);

void print_port(struct port_info *port, enum scan_type type, t_options *opts) {
    int ret;
    unsigned int padding;
    if (opts->open == true && port->state != PORT_OPENED &&
        port->state != PORT_OPEN_FILTERED)
        return;
    ret = printf("%hu/%s", port->port, type == SCAN_UDP ? "udp" : "tcp");
    padding = 8 - ret;
    ret = printf("%*s%s", padding, "", port_state_strings[port->state]);
    padding = 14 - (ret - padding);
    if (opts->no_service == false) {
        ret = printf(
            "%*s%s", padding, "",
            retrieve_service_name(type, port->port,
                                  opts->services_vec)); // service empty for now
        padding = 16 - (ret - padding);
    }
    if (opts->reason || opts->verbose > 0) {
        ret = printf("%*s%s", padding, "", reason_strings[port->reason.type]);
        if (port->reason.ttl)
            ret += printf(" ttl %hhu", port->reason.ttl);
        padding = 16 - (ret - padding);
    }
    if (opts->verbose > 0 && port->error) {
        printf("%*s", padding, "");
        print_nmap_error(port->error);
    }
    printf("\n");
}

void print_ports(struct scan_result *scan, t_options *opts) {
    printf("%-8s%-14s", "PORT", "STATE");
    if (opts->no_service == false)
        printf("%-16s", "SERVICE");
    if (opts->reason || opts->verbose > 0)
        printf("%-16s", "REASON");
    if (opts->verbose > 0)
        printf("ERROR");
    printf("\n");
    for (uint16_t i = 0; i < scan->nbr_port; i++) {
        print_port(&scan->ports[i], scan->type, opts);
    }
}

void print_scan_result(struct scan_result *result, struct host *host,
                       t_options *opts) {
    (void)opts;

    switch (result->type) {
    case SCAN_DNS:
        if (host->state <= STATE_RESOLVE_FAILED &&
            host->state != STATE_DOUBLOON && host->state != STATE_ERROR) {
            printf("DNS: failed");
            if (result->error) {
                printf(", ");
                print_nmap_error(result->error);
            }
        } else {
            printf("DNS: success, %s", inet_ntoa(host->addr.sin_addr));
            if (result->error == NULL && host->hostname_rsvl == NULL)
                printf(" (not resolved)");
            else if (result->error)
                printf(" (failed to resolve)");
            else
                printf(" (%s)", host->hostname_rsvl);
        }
        break;
    case SCAN_PING:
        printf(
            "PING: %s, %hu/%hu port, reason: %s",
            (host->state > STATE_UP ? "UP" : host_state_strings[host->state]),
            (result->nbr_port - result->remaining), result->nbr_port,
            reason_strings[result->ports->reason.type]);
        if (result->error) {
            printf(", ");
            print_nmap_error(result->error);
        } else {
            for (unsigned int i = result->nbr_port - 1; i; i--) {
                if (result->ports[i].error) {
                    printf(", ");
                    print_nmap_error(result->ports[i].error);
                    break;
                }
            }
        }
        if (result->ports->reason.ttl != 0 || result->ports->reason.rtt != 0.f)
            printf(" (ttl = %hhu, rtt = %.2f ms)", result->ports->reason.ttl,
                   result->ports->reason.rtt);
        break;
    default:
        printf("%s: %hu ports\n", scan_type_strings[result->type],
               result->nbr_port);
        print_ports(result, opts);
        break;
    }
    printf("\n");
}

/// Cmp function to sort port vector
static int cmp(void *a, void *b) {
    if (((struct port_info *)a)->port < ((struct port_info *)b)->port)
        return (-1);
    else
        return (1);
}

void print_host_result(struct host *host, t_options *opts) {
    (void)opts;
    if (host->state == STATE_DOUBLOON) {
        printf("---\nHOST RESULT for %s : DUPLICATED\n---\n", host->hostname);
        return;
    }
    printf("---\nHOST RESULT for %s (%s / %s) : %s\n", host->hostname,
           inet_ntoa(host->addr.sin_addr),
           host->hostname_rsvl ? host->hostname_rsvl : "unkown",
           host_state_strings[host->state]);
    print_scan_result(&host->scans[SCAN_DNS], host, opts);
    if (host->state == STATE_RESOLVE_FAILED) {
        printf("---\n");
        return;
    }
    for (unsigned int i = SCAN_PING; i < SCAN_NBR; i++) {
        if (host->scans[i].state > SCAN_DISABLE) {
            if (ft_merge_sort(host->scans[i].ports, host->scans[i].nbr_port,
                              cmp, false))
                error(-1, errno, "sorting port vector");
            print_scan_result(&host->scans[i], host, opts);
        }
    }
    printf("---\n");
}