#include <errno.h>
#include <error.h>
#include <nmap.h>
#include <poll.h>
#include <string.h>
#include <termios.h>

void print_worker(struct worker_handle *worker);
void print_task(struct task_handle *task);
void print_host(struct host *);
void print_scan_state(struct scan_result *scan);

void setup_stdin_non_block() {
    static struct termios newt;

    tcgetattr(STDIN_FILENO, &newt);
    newt.c_lflag &= ~(ICANON); // mode raw
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
}

void user_input(struct host *vec_hosts,
                struct worker_handle workers_pool[MAX_WORKER],
                t_options *opts) {
    char buff[128];
    ssize_t ret;
    struct pollfd fd = {.fd = 0, .events = POLLIN};
    (void)opts;

    if (poll(&fd, 1, 0) > 0) {
        ret = read(0, buff, 128);
        write(1, buff, ret);
        write(1, "\n", 1);
        if (ret < 0)
            error(1, errno, "reading user input");
        if (ret == 0)
            return;
        switch (buff[0]) {
        case 'h':
            ft_vector_iter(vec_hosts, (void (*)(void *))print_host);
            break;
        case 'w':
            for (unsigned int i = 0; i < MAX_WORKER; i++) {
                if (workers_pool[i].state != WORKER_AVAILABLE)
                    print_worker(&workers_pool[i]);
            }
            break;
        case 'D':
            if (opts->verbose > 0)
                opts->verbose--;
            printf("Decreased verbosity to %u\n", opts->verbose);
            break;
        case 'd':
            if (opts->verbose < 5)
                opts->verbose++;
            printf("Increased verbosity to %u\n", opts->verbose);
            break;
        case 't':
            opts->trace_packet = true;
            printf("Enabled packet tracing\n");
            break;
        case 'T':
            opts->trace_packet = false;
            printf("Disabled packet tracing\n");
            break;
        }
    }
}