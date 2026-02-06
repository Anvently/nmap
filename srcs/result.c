#include <arpa/inet.h>
#include <netinet/ip.h>
#include <nmap.h>

extern const char *reason_strings[10];
extern const char *host_state_strings[14];
extern const char *scan_type_strings[11];

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
        break;
    }
    printf("\n");
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
        } else
            printf(" (ttl = %hhu, rtt = %.2f ms)", result->ports->reason.ttl,
                   result->ports->reason.rtt);
        break;
    default:
        printf("%s: %hu ports", scan_type_strings[result->type],
               result->nbr_port);
        break;
    }
    printf("\n");
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
    if (host->state > STATE_RESOLVE_FAILED)
        print_scan_result(&host->scans[SCAN_PING], host, opts);
    if (host->state < STATE_SCAN_PENDING) {
        printf("---\n");
        return;
    }
    for (unsigned int i = SCAN_PING + 1; i < SCAN_NBR; i++) {
        if (host->scans[i].state > SCAN_DISABLE)
            print_scan_result(&host->scans[i], host, opts);
    }
    printf("---\n");
}