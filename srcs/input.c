#include <errno.h>
#include <error.h>
#include <nmap.h>
#include <poll.h>
#include <string.h>

void print_worker(struct worker_handle *worker);
void print_task(struct task_handle *task);
void print_host(struct host *);
void print_scan_state(struct scan_result *scan);

void user_input(struct host *vec_hosts, struct worker_handle *vec_workers,
                t_options *opts) {
    char buff[128];
    ssize_t ret;
    struct pollfd fd = {.fd = 0, .events = POLLIN};
    (void)opts;

    if (poll(&fd, 1, 0) > 0) {
        ret = read(0, buff, 128);
        if (ret < 0)
            error(1, errno, "reading user input");
        if (ret == 0)
            return;
        buff[ret - 1] = '\0';
        if (strncmp("h", buff, 1) == 0) {
            ft_vector_iter(vec_hosts, (void (*)(void *))print_host);
        } else if (strncmp("w", buff, 1) == 0) {
            ft_vector_iter(vec_workers, (void (*)(void *))print_worker);
        }
    }
}