#include <nmap.h>

void print_worker(struct worker_handle *worker);

static void cleanup(void *arg) {
    struct task_handle *task;
    struct worker_handle *worker = (struct worker_handle *)arg;
    size_t i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->flags.initialized == 1 && task->release)
            task->release(task);
        task->flags.done = 1;
    }
    worker->state = WORKER_DONE;
}

static void init_tasks(struct worker_handle *worker) {
    struct task_handle *task;
    size_t i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->init && task->init(task) != 0) {
            continue;
        }
        task->flags.initialized = 1;
    }
}

unsigned int count_runnning_tasks(struct worker_handle *worker) {
    struct task_handle *task;
    unsigned int running;
    unsigned int i = running = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->flags.cancelled || task->flags.done)
            running--;
    }
    return (running);
}

void *worker_routine(void *data) {
    struct worker_handle *worker = (struct worker_handle *)data;
    unsigned int running;

    printf("starting thread\n");
    print_worker(worker);
    pthread_cleanup_push(cleanup, worker);

    init_tasks(worker);
    running = count_runnning_tasks(worker);
    while (running > 0) {
        sleep(1);
    }

    pthread_cleanup_pop(1);
    pthread_exit(worker);
    return (NULL);
}