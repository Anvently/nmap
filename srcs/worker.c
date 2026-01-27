#include <nmap.h>

void print_worker(struct worker_handle *worker);

void *worker_routine(void *data) {
    struct worker_handle *worker = (struct worker_handle *)data;
    const size_t nbr_task = ft_vector_size(worker->tasks_vec);
    struct task_handle *task;

    printf("starting thread\n");
    print_worker(worker);
    while (1) {
        usleep(1000);
        for (size_t i = 0; i < nbr_task; i++) {
            task = &worker->tasks_vec[i];
            if (task == SCAN_DNS) {
                task->packet_send(task);
                worker->state = WORKER_DONE;
                pthread_exit(NULL);
            }
        }
    }
    return (NULL);
}