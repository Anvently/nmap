#include <errno.h>
#include <error.h>
#include <nmap.h>
#include <poll.h>
#include <string.h>

void print_worker(struct worker_handle *worker);
void print_task(struct task_handle *task);
void print_host(struct host *);
void print_scan_state(struct scan_result *scan);

void user_input(struct host *vec_hosts,
                struct worker_handle workers_pool[MAX_WORKER],
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
            for (unsigned int i = 0; i < MAX_WORKER; i++) {
                if (workers_pool[i].state != WORKER_AVAILABLE)
                    print_worker(&workers_pool[i]);
            }
        }
    }
}