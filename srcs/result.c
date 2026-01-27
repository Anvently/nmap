#include <nmap.h>

void print_task_result(struct task_handle *task) { (void)task; }

void print_scan_result(struct scan_result *result, t_options *opts) {
    (void)result;
    (void)opts;
}

void print_host_result(struct host *host, t_options *opts) {
    (void)host;
    (void)opts;
}