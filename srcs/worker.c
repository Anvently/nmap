#include <nmap.h>
#include <poll.h>
#include <string.h>

void print_worker(struct worker_handle *worker);
void print_nmap_error(struct nmap_error *error);

static void task_error(struct nmap_error **error_ptr, enum nmap_error_type type,
                       const char *func_fail, const char *detail) {
    struct nmap_error *error;

    if (*error_ptr) {
        printf("warning: this error will be overidden\n");
        print_nmap_error(*error_ptr);
        free(*error_ptr);
    }
    *error_ptr = error = calloc(1, sizeof(struct nmap_error));
    if (error == NULL)
        return;
    error->type = type;
    strlcpy(error->u.dns.func_fail, func_fail, sizeof(error->u.dns.func_fail));
    strlcpy(error->u.dns.description, detail, sizeof(error->u.dns.description));
}

static void release_task(struct task_handle *task) {
    if (task->flags.initialized == 0) // @warning: this implies that worker does
                                      // not release task if init error, it's
                                      // the scan responsability to do it
        return;
    if (task->sock_main.pollfd) {
        task->sock_main.pollfd->events = 0;
        task->sock_main.pollfd = NULL;
    }
    if (task->sock_icmp.pollfd) {
        task->sock_icmp.pollfd->events = 0;
        task->sock_icmp.pollfd = NULL;
    }
    if (task->release)
        task->release(task);
    task->flags.initialized = 0;
    task->flags.done = 1;
}

static void cleanup(void *arg) {
    struct task_handle *task;
    struct worker_handle *worker = (struct worker_handle *)arg;
    size_t i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->flags.initialized)
            release_task(task);
    }
    worker->state = WORKER_DONE;
}

static void free_vector(void *arg) { ft_vector_free((t_vector **)&arg); }

static void cancel_worker(struct worker_handle *worker) {
    struct task_handle *task;
    size_t i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->flags.done == 1)
            continue;
        task_error(task->error, NMAP_ERROR_WORKER, "system error",
                   "in worker routine");
        task->flags.cancelled = 1;
    }
    worker->state = WORKER_DONE;
}

static int register_pollfd(struct sock_instance *instance,
                           struct pollfd *vec_pollfds) {
    struct pollfd pollfd = {.fd = instance->fd,
                            .events = POLLIN | POLLERR | POLLHUP};

    if (ft_vector_push((t_vector **)&vec_pollfds, &pollfd))
        return (1);
    instance->pollfd = &vec_pollfds[ft_vector_size(vec_pollfds) - 1];
    return (0);
}

static void init_tasks(struct worker_handle *worker,
                       struct pollfd *vec_pollfds) {
    struct task_handle *task;

    size_t i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->init && task->init(task) != 0) {
            task->flags.done = 1;
            continue;
        }
        if (task->sock_main.fd >= 0)
            register_pollfd(&task->sock_main, vec_pollfds);
        if (task->sock_icmp.fd >= 0)
            register_pollfd(&task->sock_icmp, vec_pollfds);
        task->flags.initialized = 1;
    }
}

/// @brief Loop every task, counting the one still running. Behave differently
/// for :
/// - task waiting a response : update ```timeout``` argument with the minimum
/// timeout encountered, decrementing timeout for each task with elapsed time
/// between 2 calls and checking for the one for which the timeout is expired.
///- task for which no probe was sent : send a probe
/// @param worker
/// @param
/// @return
static unsigned int loop_running_tasks(struct worker_handle *worker,
                                       struct timeval *min_timeout) {
    struct task_handle *task;
    unsigned int running;
    unsigned int i = running = ft_vector_size(worker->tasks_vec);
    static struct timeval last = {.tv_sec = 0, .tv_usec = 0};
    struct timeval current, elapsed = {0};

    gettimeofday(&current, NULL);
    if (timerisset(&last))
        timersub(&current, &last, &elapsed); // elapsed = current - last
    last = current;
    while (i--) {
        task = &worker->tasks_vec[i];
        if (task->flags.cancelled || task->flags.done) {
            running--;
            continue;
        }
        if (task->flags.send_state == 1) { // Something was sent
            timersub(&task->timeout, &elapsed,
                     &task->timeout);       // timeout = timeout - elapsed
            if (task->timeout.tv_sec < 0) { // TIMEOUT
                task->flags.timeout = 1;
                if (task->packet_timeout && task->packet_timeout(task)) {
                    running--;
                    release_task(task);
                    continue;
                }
                task->flags.send_state = 0;
            }
            if (timercmp(&task->timeout, min_timeout, <)) {
                // Polling timeout will be set to this timeout
                *min_timeout = task->timeout;
            }
        } else if (task->packet_send) { // Nothing was sent yet (task was just
                                        // initialized or something
            // received and read but no answer was sent immediately)
            task->timeout = (struct timeval){.tv_sec = DFT_TASK_TIMEOUT};
            if (task->packet_send(task)) {
                release_task(task);
                continue;
                ;
            }
            if (timercmp(&task->timeout, min_timeout, <)) {
                // Polling timeout will be set to this timeout
                *min_timeout = task->timeout;
            }
        } else { // INFINITE CONDITION
            task_error(task->error, NMAP_ERROR_WORKER, "deadlock detected",
                       "task is in send state but no send handler provided");
            task->flags.error = 1;
            task->flags.done = 1;
        }
    }
    return (running);
}

static void handle_rcv(struct worker_handle *worker, unsigned int nrecv) {
    struct task_handle *task;
    unsigned int i = ft_vector_size(worker->tasks_vec);

    while (i-- && nrecv > 0) {
        task = &worker->tasks_vec[i];
        if (task->flags.done == 1)
            continue; // Any completed (or cancelled task) should have its fd
                      // removed from polling instance
        if (task->sock_main.pollfd && task->sock_main.pollfd->events) {
            nrecv--;
            if (task->packet_rcv && task->packet_rcv(task, &task->sock_main))
                release_task(task);
        }
        if (task->sock_icmp.pollfd && task->sock_icmp.pollfd->events) {
            nrecv--;
            if (task->packet_rcv && task->packet_rcv(task, &task->sock_icmp))
                release_task(task);
        }
    }
}

static void worker_loop(struct worker_handle *worker, struct pollfd *pollfds) {
    unsigned int running;
    struct timeval timeout = {.tv_sec = LONG_MAX, .tv_usec = 0};
    int ret;

    running = loop_running_tasks(worker, &timeout);
    while (running > 0) {
        ret = poll(pollfds, worker->nbr_sock,
                   timeout.tv_sec * 1e3 + timeout.tv_usec / 1e3);
        switch (ret) {
        case 0: // timeout
            break;
        case -1: // error
            cancel_worker(worker);
            return;
        default:
            handle_rcv(worker, ret);
            break;
        }
        running = loop_running_tasks(worker, &timeout);
    }
}

void *worker_routine(void *data) {
    struct worker_handle *worker = (struct worker_handle *)data;
    struct pollfd *vec_pollfds =
        worker->nbr_sock > 0
            ? ft_vector_create(sizeof(struct pollfd), worker->nbr_sock)
            : NULL;

    pthread_cleanup_push(cleanup, worker);
    pthread_cleanup_push(free_vector, vec_pollfds);
    if (worker->nbr_sock > 0 && vec_pollfds == NULL) {
        cancel_worker(worker);
        pthread_exit(worker);
    }
    init_tasks(worker, vec_pollfds);
    worker_loop(worker, vec_pollfds);

    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    pthread_exit(worker);
    return (NULL);
}