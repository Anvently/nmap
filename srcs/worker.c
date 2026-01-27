#include <nmap.h>

void print_worker(struct worker_handle *worker);

void *worker_routine(void *data) {
    struct worker_handle *worker = (struct worker_handle *)data;

    printf("starting thread\n");
    print_worker(worker);
    while (1) {
        usleep(1000);
    }
    return (NULL);
}