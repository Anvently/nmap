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
                printf("%hu (%s, %s", task->io_data.tcp.ports[i].port,
                       port_state_strings[task->io_data.tcp.ports[i].state],
                       reason_strings[task->io_data.tcp.ports[i].reason.type]);
                if (task->io_data.tcp.ports[i].reason.rtt > 0.f)
                    printf(", %.2f", task->io_data.tcp.ports[i].reason.rtt);
                printf("), ");
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

    ret = printf("%hu/%s", port->port, type == SCAN_UDP ? "udp" : "tcp");
    padding = 10 - ret;
    ret = printf("%*s%s", padding, "", port_state_strings[port->state]);
    padding = 16 - (ret - padding);
    if (opts->no_service == false) {
        ret = printf(
            "%*s%s", padding, "",
            retrieve_service_name(type, port->port,
                                  opts->services_vec)); // service empty for now
        padding = 16 - (ret - padding);
    }
    if (opts->verbose > 0) {
        ret = printf("%*s%s", padding, "", reason_strings[port->reason.type]);
        if (port->reason.ttl)
            ret += printf(" ttl %hhu", port->reason.ttl);
        if (port->reason.rtt)
            ret += printf(" rtt %.2f", port->reason.rtt);
        padding = 24 - (ret - padding);
    }
    if (opts->verbose > 0 && port->error) {
        printf("%*s", padding, "");
        print_nmap_error(port->error);
    }
    printf("\n");
}

void print_ports(struct scan_result *scan, t_options *opts) {
    printf("%-10s%-16s", "PORT", "STATE");
    if (opts->no_service == false)
        printf("%-16s", "SERVICE");
    if (opts->verbose > 0)
        printf("%-24s", "REASON");
    if (opts->verbose > 0)
        printf("ERROR");
    printf("\n");
    for (uint16_t i = 0; i < scan->nbr_port; i++) {
        if (opts->open && (scan->ports[i].state != PORT_OPENED &&
                           scan->ports[i].state != PORT_OPEN_FILTERED))
            continue;
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

struct summary {
    enum port_state *conclusions;
    unsigned int service_width;
    unsigned int scan_column_widths[SCAN_NBR];
    uint16_t nport_state[PORT_STATE_NBR];
};

static void print_port_conclusion(struct host *host, struct summary *summary,
                                  uint16_t port_idx, t_options *opts) {
    const uint16_t port = opts->port_vec[port_idx];
    const enum port_state conclusion = summary->conclusions[port_idx];

    if (opts->open == true && conclusion != PORT_OPENED &&
        conclusion != PORT_OPEN_FILTERED && conclusion != PORT_ERROR)
        return;
    printf("%1$-6hu%2$-*3$.*3$s", port,
           retrieve_service_name(SCAN_SYN, port, opts->services_vec),
           summary->service_width);
    for (unsigned int i = SCAN_SYN; i < SCAN_NBR; i++) {
        if (host->scans[i].state != SCAN_DONE)
            continue;
        printf("%-*s", summary->scan_column_widths[i],
               port_state_strings[host->scans[i].ports[port_idx].state]);
    }
    printf("%s\n", port_state_strings[conclusion]);
}

static void conclude_ports_state(struct host *host, struct summary *summary,
                                 t_options *opts) {
    static unsigned int state_width[PORT_STATE_NBR] = {8,  9,  7,  7, 9,
                                                       11, 16, 16, 6};
    const uint16_t nbr_port = (uint16_t)ft_vector_size(opts->port_vec);

    // Conclude on port state by iterating over every port and every scan result
    for (uint16_t i = 0; i < nbr_port; i++) {
        summary->conclusions[i] = PORT_UNKNOWN;
        if (opts->no_service == false) {
            const char *service_name = retrieve_service_name(
                SCAN_SYN, opts->port_vec[i], opts->services_vec);
            summary->service_width =
                ft_max_u(summary->service_width, strlen(service_name) + 1);
        }
        for (unsigned int scan_idx = SCAN_PING + 1; scan_idx < SCAN_NBR;
             scan_idx++) {
            if (host->scans[scan_idx].state != SCAN_DONE)
                continue;
            struct port_info *port_info = &host->scans[scan_idx].ports[i];
            summary->scan_column_widths[scan_idx] =
                ft_max_u(state_width[port_info->state],
                         summary->scan_column_widths[scan_idx]);

            switch (port_info->state) {
            case PORT_SCANNING:
            case PORT_UNKNOWN:
                break; // Not supposed to happen
            default:
                // Small port_state take precedence over high port_state in enum
                if (summary->conclusions[i] == PORT_UNKNOWN ||
                    summary->conclusions[i] > port_info->state)
                    summary->conclusions[i] = port_info->state;
                break;
            }
        }
    }
    // Count each port state occurence
    for (uint16_t i = 0; i < nbr_port; i++)
        summary->nport_state[summary->conclusions[i]] += 1;
    for (unsigned int i = SCAN_PING + 1; i < SCAN_NBR; i++) {
        if (host->scans[i].state != SCAN_DONE)
            continue;
        summary->scan_column_widths[i] = ft_max_u(
            summary->scan_column_widths[i], strlen(scan_type_strings[i]) + 1);
    }
}

static void print_ports_summary(struct host *host, t_options *opts,
                                bool summary_only) {
    const uint16_t nbr_port = (uint16_t)ft_vector_size(opts->port_vec);
    struct summary summary = {.scan_column_widths = {0},
                              .service_width = 0,
                              .conclusions =
                                  malloc(nbr_port * sizeof(enum port_state)),
                              .nport_state = {0}};
    bool first_state = true;

    if (summary.conclusions == NULL) {
        printf("Failed to allocate port state conclusion vector.\n");
        return;
    }
    conclude_ports_state(host, &summary, opts);
    // Print summary
    printf("Result: ");
    for (unsigned int i = 0; i < PORT_STATE_NBR; i++) {
        if (summary.nport_state[i] == 0)
            continue;
        printf("%s%hu %s", first_state ? "" : ", ", summary.nport_state[i],
               port_state_strings[i]);
        first_state = false;
    }
    if (summary_only) {
        printf("\n");
        return;
    }
    printf("\n%1$-6s%2$-*3$.*3$s", "PORT", "SERVICE", summary.service_width);
    for (unsigned int i = SCAN_PING + 1; i < SCAN_NBR; i++) {
        printf("%1$-*2$.*2$s", scan_type_strings[i],
               summary.scan_column_widths[i]);
    }
    printf("CONCLUSION\n");
    for (uint16_t i = 0; i < nbr_port; i++) {

        if (opts->open == false || summary.conclusions[i] == PORT_OPENED ||
            summary.conclusions[i] == PORT_OPEN_FILTERED ||
            summary.conclusions[i] == PORT_ERROR)
            print_port_conclusion(host, &summary, i, opts);
    }
    free(summary.conclusions);
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
    if (host->scans[SCAN_PING].state > SCAN_DISABLE) {
        print_scan_result(&host->scans[SCAN_PING], host, opts);
    }
    if (host->state < STATE_UP) {
        printf("---\n");
        return;
    }
    // Iterate enable scan result and sort port result in order
    for (unsigned int i = SCAN_PING; i < SCAN_NBR; i++) {
        if (host->scans[i].state == SCAN_DONE) {
            if (ft_merge_sort(host->scans[i].ports, host->scans[i].nbr_port,
                              cmp, false))
                error(-1, errno, "sorting port vector");
            // if (opts->verbose > 0)
            //     print_scan_result(&host->scans[i], host, opts);
        }
    }
    print_ports_summary(host, opts, opts->verbose != 0);

    printf("---\n");
}