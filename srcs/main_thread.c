#include <errno.h>
#include <error.h>
#include <memory.h>
#include <nmap.h>
#include <string.h>

struct host *hosts_create(char **args, unsigned int nbr_args, t_options *opts);
void hosts_free(struct host **hosts);

void print_host_result(struct host *host, t_options *opts);
void print_scan_result(struct scan_result *result, struct host *host,
                       t_options *opts);
void print_task_result(struct task_handle *task);
void print_task(struct task_handle *task);
void print_worker(struct worker_handle *worker);
;

void *worker_routine(void *data);

void user_input(struct host *vec_hosts,
                struct worker_handle workers_pool[MAX_WORKER], t_options *opts);

int dns_init(struct task_handle *data);
int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data, struct sock_instance *sock);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

struct host *check_double_host(struct host *vec_hosts, struct host *host);

/// @brief
/// @param vec_hosts
/// @param skip_blocking If enable, blocking scan will not be considered as
/// candidate
/// @return
static struct host *find_available_host(struct host *vec_hosts,
                                        bool skip_blocking) {

    const size_t vec_size = ft_vector_size(vec_hosts);
    // struct scan_result *udp_scan;

    for (unsigned int i = 0; i < vec_size; i++) {
        switch (vec_hosts[i].state) {
        case STATE_PENDING_RESOLVE:
            if (skip_blocking)
                continue;
            return (&vec_hosts[i]);
        case STATE_PING_PENDING:
            return (&vec_hosts[i]);

        default: // For now DNS and ping only
            continue;

            // case STATE_SCAN_PENDING:
            //     return (&vec_hosts[i]);

            // case STATE_SCAN_RUNNING:
            //     // If UDP disabled
            //     udp_scan = &vec_hosts[i].scans[SCAN_UDP];
            //     if (udp_scan->state == SCAN_DISABLE || udp_scan->state ==
            //     SCAN_DONE)
            //         continue;
            //     if (udp_scan->remaining > 0)
            //         return &vec_hosts[i];
            //     break;

            // default:
            //     continue;
        }
    }
    return (NULL);
}

/// @brief May be recursively called if state has changed
/// @param host
/// @return ```1``` if state is a terminal state, else ```0```
static int switch_state(struct host *host) {
    switch (host->state) {

    /// Final states
    case STATE_DOUBLOON:
    case STATE_ERROR:
    case STATE_DOWN:
    case STATE_PING_TIMEOUT:
    case STATE_RESOLVE_FAILED:
    case STATE_SCAN_DONE:
        return (1);

    /// These state should be handled by a task assignment
    case STATE_PENDING_RESOLVE:
    case STATE_PING_PENDING:
    case STATE_SCAN_PENDING:
        return (0);

    /// These state must be handled by task_done or task_cancelled
    case STATE_RESOLVING:
    case STATE_PING_SENT:
        return (0);

    case STATE_RESOLVED:
        if (host->scans[SCAN_PING].state == SCAN_PENDING)
            host->state = STATE_PING_PENDING;
        else
            host->state = STATE_UP;
        return (switch_state(host));

    case STATE_UP:
        for (uint8_t i = SCAN_SYN; i < SCAN_NBR; i++) {
            if (host->scans[i].state != SCAN_DISABLE) {
                host->state = STATE_SCAN_PENDING;
                break;
            }
            host->state = STATE_SCAN_DONE;
        }
        return (switch_state(host));

    case STATE_SCAN_RUNNING:
        host->state = STATE_SCAN_DONE;
        for (uint8_t i = SCAN_SYN; i < SCAN_NBR; i++) {
            if (host->scans[i].state == SCAN_PENDING)
                host->state = STATE_SCAN_PENDING;
            if (host->scans[i].state == SCAN_RUNNING) {
                host->state = STATE_SCAN_RUNNING;
                return (0);
            }
        }
        return (switch_state(host));
    }
    return (0);
}

/// @brief Must be called once task compatibility verification is done. Host
/// status will be be updated.
/// @param task
static void confirm_task(struct task_handle *task) {
    struct host *host = task->host;
    switch (task->scan_type) {
    case SCAN_DNS:
        host->state = STATE_RESOLVING;
        host->current_scan.dns = 1;
        host->scans[SCAN_DNS].state = SCAN_RUNNING;
        break;
    case SCAN_PING:
        host->state = STATE_PING_SENT;
        host->current_scan.ping = 1;
        host->scans[SCAN_PING].state = SCAN_RUNNING;
        task->data.ping.rslt->state = PORT_SCANNING;
        break;
    default:
        host->state = STATE_SCAN_RUNNING;
        if (task->scan_type != SCAN_RAW_UDP) {
            host->current_scan.int_representation |= (1 << task->scan_type);
            host->scans[task->scan_type].state = SCAN_RUNNING;
        } else {
            host->current_scan.raw_udp = 1;
            host->scans[SCAN_UDP].state = SCAN_RUNNING;
        }
        break;
    }
}
/// @brief Fill ```task``` with an available task in ```host``` and update
/// ```host``` status
/// @param host
/// @param task
/// @param nbr_socket used to increment the number of sockets the worker has to
/// manage. Blocking task  (```SCAN_DNS``` and ```SCAN_CONNECT```) will be
/// rejeced if nbr_socket > 0
/// @return ```false``` if no available task
static bool assign_task(struct host *host, struct task_handle *task,
                        unsigned int *nbr_socket, t_options *opts) {
    bool ret = false;
    // Only relevant to print debug message when task is started
    bool scan_started = false;
    bool skip_blocking = *nbr_socket > 0;

    task->opts = opts;
    switch (host->state) {
    case STATE_PENDING_RESOLVE:
        task->scan_type = SCAN_DNS;
        task->init = dns_init;
        task->packet_rcv = NULL;
        task->packet_timeout = NULL;
        task->release = NULL;
        task->packet_send = NULL;
        task->timeout = (struct timeval){0};
        task->data.dns.hostname_rslv = NULL;
        task->data.dns.addr = (struct sockaddr_in){0};
        task->data.dns.hostname = host->hostname;
        task->data.dns.dont_resolve = (opts->numeric ? true : false);
        task->error = &host->scans[SCAN_DNS].error;
        task->host = host;
        ret = true;
        scan_started = true;
        break;

    case STATE_PING_PENDING:
        task->scan_type = SCAN_PING;
        task->init = ping_init;
        task->packet_send = ping_packet_send;
        task->packet_rcv = ping_packet_rcv;
        task->packet_timeout = ping_packet_timeout;
        task->release = ping_release;
        task->timeout = (struct timeval){.tv_sec = PING_TIMEOUT, .tv_usec = 0};
        task->data.ping.daddr = host->addr.sin_addr;
        task->data.ping.rslt = &host->scans[SCAN_PING].ports[0];
        task->error = &host->scans[SCAN_PING].error;
        task->data.ping.saddr = (struct sockaddr_in){0};
        nbr_socket += 1; // Only TCP sock for now
        task->sock_eph.fd = -1;
        task->sock_icmp = (struct sock_instance){.fd = -1};
        task->sock_main = (struct sock_instance){.fd = -1};
        task->host = host;
        ret = true;
        if (task->data.ping.rslt->retries == 0)
            scan_started = true;
        break;

    default: // For now DNS and PING only
        return (false);
    }
    if (skip_blocking &&
        (task->scan_type == SCAN_DNS || task->scan_type == SCAN_CONNECT))
        return (false);
    confirm_task(task);
    if (opts->verbose > 0 && scan_started) {
        extern const char *scan_type_strings[11];
        printf("%s scan started, host %s\n", scan_type_strings[task->scan_type],
               task->host->hostname);
    }
    return (ret);
}

/// @brief Count how many host are in given state or above
/// @param vec_hosts
/// @param opts
/// @return
unsigned int count_state(struct host *vec_hosts, enum host_state state) {
    const size_t nbr_host = ft_vector_size(vec_hosts);
    unsigned int n = 0;
    for (unsigned int i = 0; i < nbr_host; i++) {
        if (vec_hosts->state >= state)
            n++;
    }
    return (n);
}

/// @brief Return ```false``` if any host have some task left to do.
/// @param vec_host
/// @return
static bool check_hosts_done(struct host *vec_hosts) {
    size_t i = ft_vector_size(vec_hosts);
    while (i--) {
        switch (vec_hosts[i].state) {
        case STATE_PENDING_RESOLVE:
        case STATE_RESOLVING:
        case STATE_PING_PENDING:
        case STATE_PING_SENT:
        case STATE_SCAN_PENDING:
        case STATE_SCAN_RUNNING:
            return (false);

        default:
            break;
        }
    }
    return (true);
}

/* Main loop
1. If worker < MAX_WORKER : find an available host (state >= 3 && state <
12)
2. If host
    - allocate and initialize tasks for workers
        - if UDP scan enabled and not done :
            - assign MAX_TASK_WORKER - other_task? - remaining_udp_port
        - else:
            - assign a single task
    - create a worker with tasks assigned
3. Non-blocking join :
    - if join, decrement worker, and update host state.
        - if -vv is one, prints task result
    - if a scan is done and -v, prints it
    - if a host is done, prints it
    - if all state done, break loop

*/

static void handle_task_cancelled(struct task_handle task, t_options *opts) {
    struct scan_result *scan;

    scan = &task.host->scans[task.scan_type];
    switch (scan->type) {
    case SCAN_DNS: // Should not happen
        --scan->assigned_worker;
        scan->state = SCAN_PENDING;
        task.host->state = STATE_PENDING_RESOLVE;
        task.host->current_scan.dns = 0;
        break;
    case SCAN_PING:
        --scan->assigned_worker;
        task.host->current_scan.ping = 0;
        if (++scan->ports[0].retries >= MAX_RETRIES) {
            scan->state = SCAN_DONE;
            scan->ports->reason.type = REASON_ERROR;
            task.host->state = STATE_ERROR;
            break;
        }
        scan->state = SCAN_PENDING;
        task.host->state = STATE_PING_PENDING;
        break;
    default:
        break;
    }
    if (task.host->state != STATE_ERROR && *task.error) {
        free(*task.error);
        *task.error = NULL;
    }
    if (task.host->state == STATE_ERROR)
        print_host_result(task.host, opts);
}

static void handle_task_done(struct task_handle task, struct host *vec_hosts,
                             t_options *opts) {
    struct scan_result *scan;
    bool ret;

    if ((task.flags.error == 1 && opts->verbose > 0) || opts->verbose > 1)
        print_task_result(&task);
    scan = &task.host->scans[task.scan_type];
    switch (scan->type) {
    case SCAN_DNS:
        scan->assigned_worker--;
        task.host->current_scan.dns = 0;
        task.host->hostname_rsvl = task.data.dns.hostname_rslv;
        task.host->addr = task.data.dns.addr;
        if (task.flags.error) {
            task.host->state = STATE_RESOLVE_FAILED;
        } else {
            task.host->state = STATE_RESOLVED;
            if (check_double_host(vec_hosts, task.host)) { //
                task.host->state = STATE_DOUBLOON;
            }
        }
        scan->state = SCAN_DONE;
        break;
    case SCAN_PING:
        scan->assigned_worker--;
        task.host->current_scan.ping = 0;
        if (*task.error && (*task.error)->type == NMAP_ERROR_WORKER) {
            scan->ports[0].reason.type = REASON_ERROR;
        }
        switch (scan->ports[0].reason.type) {
        case REASON_NO_RESPONSE:
            if (++scan->ports[0].retries >= MAX_RETRIES) {
                scan->state = SCAN_DONE;
                scan->ports->reason.type = REASON_NO_RESPONSE;
                task.host->state = STATE_PING_TIMEOUT;
                scan->state = SCAN_DONE;
                break;
            }
            task.host->state = STATE_PING_PENDING;
            scan->state = SCAN_PENDING;
            break;

        case REASON_HOST_UNREACH:
            task.host->state = STATE_DOWN;
            scan->state = SCAN_DONE;
            break;

        case REASON_ERROR:
            task.host->state = STATE_ERROR;
            scan->state = SCAN_DONE;
            break;

        default:
            task.host->state = STATE_UP;
            scan->state = SCAN_DONE;
            break;
        }
        break;
    default:
        break;
    }
    ret = switch_state(task.host);
    if (scan->state == SCAN_DONE && opts->verbose > 0) {
        printf("Scan done, host %s\n", task.host->hostname);
        print_scan_result(scan, task.host, opts);
    }
    if (ret)
        print_host_result(task.host, opts);
}

static void handle_worker_result(struct worker_handle *worker, void *ret,
                                 struct host *vec_hosts, t_options *opts) {
    (void)ret;

    unsigned int i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        if (worker->tasks_vec[i].flags.cancelled == 0) {
            handle_task_done(worker->tasks_vec[i], vec_hosts, opts);
        } else {
            handle_task_cancelled(worker->tasks_vec[i], opts);
        }
    }
}

/// @brief Check if any worker wants to join, if so, handle every task it had
/// and update host status
/// @param workers_vec
/// @param opts
static void loop_worker_state(struct worker_handle *workers_pool,
                              unsigned int *nbr_workers, struct host *vec_hosts,
                              t_options *opts) {
    void *ret;
    for (unsigned int i = 0; i < MAX_WORKER && *nbr_workers > 0; i++) {
        if (workers_pool[i].state != WORKER_DONE)
            continue;
        if (pthread_join(workers_pool[i].tid, &ret))
            error(-1, errno, "joining thread");
        if (opts->verbose > 2) {
            printf("%s", TERM_CL_MAGENTA);
            printf("Worker stopped...\n");
            print_worker(&workers_pool[i]);
            printf("%s", TERM_CL_RESET);
        }
        handle_worker_result(&workers_pool[i], ret, vec_hosts, opts);
        ft_vector_free((t_vector **)&workers_pool[i].tasks_vec);
        workers_pool[i].state = WORKER_AVAILABLE;
        workers_pool[i].tid = 0;
        (*nbr_workers)--;
    }
}

/// @brief Cancel every task the ```worker``` was assigned.
/// Should be only called by main thread if the worker thread could not be
/// launched
/// @param worker
static void cancel_worker(struct worker_handle *worker, t_options *opts) {
    unsigned int i = ft_vector_size(worker->tasks_vec);
    if (opts->verbose > 2) {
        printf("%s", TERM_CL_MAGENTA);
        printf("Cancelling worker...\n");
        print_worker(worker);
        printf("%s", TERM_CL_RESET);
    }
    while (i--) {
        handle_task_cancelled(worker->tasks_vec[i], opts);
    }
    ft_vector_free((t_vector **)&worker->tasks_vec);
    worker->tid = 0;
    worker->nbr_sock = 0;
    worker->state = WORKER_AVAILABLE;
}

static struct worker_handle *
find_available_worker(struct worker_handle workers_pool[MAX_WORKER]) {
    for (unsigned int i = 0; i < MAX_WORKER; i++) {
        if (workers_pool[i].state == WORKER_AVAILABLE)
            return (&workers_pool[i]);
    }
    return (NULL);
}

/// @brief Initialize, allocate and run worker
/// @return ```NULL``` if no worker could be allocated, because of worker
/// initialisation failure or no available task, else ```address``` of allocated
/// worker in vector
static struct worker_handle *
init_worker(struct host *hosts_vec,
            struct worker_handle workers_pool[MAX_WORKER], t_options *opts) {
    struct worker_handle *worker = find_available_worker(workers_pool);
    struct task_handle task;
    struct host *host;
    bool ret;

    if (worker == NULL)
        return (NULL);
    host = find_available_host(hosts_vec, false);
    if (host == NULL)
        return (NULL);
    worker->tasks_vec =
        ft_vector_create(sizeof(struct task_handle), MAX_TASK_WORKER);
    do {
        task = (struct task_handle){0};
        ret = assign_task(host, &task, &worker->nbr_sock, opts);
        if (ret == false) { // This host has no more task
            host = find_available_host(hosts_vec, true);
            if (host)
                ret = true;
            else
                break; // If no task anymore
            continue;
        }
        if (task.scan_type == SCAN_DNS || task.scan_type == SCAN_CONNECT) {
            ret = false; // blocking task be executed by a dedicated worker
        }
        // Adds task to worker
        ft_vector_push((t_vector **)&worker->tasks_vec, &task);
    } while (ret == true &&
             ft_vector_size(worker->tasks_vec) < MAX_TASK_WORKER);
    if (ft_vector_resize((t_vector **)&worker->tasks_vec,
                         ft_vector_size(worker->tasks_vec))) {
        cancel_worker(worker, opts);
        return (NULL);
    }
    worker->state = WORKER_RUNNING;
    if (pthread_create(&worker->tid, NULL, worker_routine, worker)) {
        cancel_worker(worker, opts);
        return (NULL);
    }
    if (opts->verbose > 2) {
        printf("%s", TERM_CL_MAGENTA);
        printf("Starting worker with address %p...\n", worker);
        print_worker(worker);
        printf("%s", TERM_CL_RESET);
    }
    return (worker);
}

static int main_loop(struct host *vec_hosts, t_options *opts) {
    unsigned int nbr_workers;
    struct worker_handle workers_pool[MAX_WORKER] = {0};

    while (1) {
        user_input(vec_hosts, workers_pool, opts);
        usleep(1000); // 1ms sleep
        loop_worker_state(workers_pool, &nbr_workers, vec_hosts, opts);
        // If all state done, break_loop
        if (check_hosts_done(vec_hosts) == true)
            break;
        // Find available host
        if (nbr_workers >= MAX_WORKER)
            continue;
        if (init_worker(vec_hosts, workers_pool, opts))
            nbr_workers++;
    }
    return (0);
}

/// @brief
/// @param args equivalent to ```argv + 1```, option argument are replaced
/// with
/// ```NULL```
/// @param nbr_args number of given ```args``` in args
/// @param options
/// @return ```0``` for success
int ft_nmap(char **args, unsigned int nbr_args, t_options *opts) {
    int ret = 0;
    struct host *vec_hosts;
    // main loop
    vec_hosts = hosts_create(args, nbr_args, opts);
    ret = main_loop(vec_hosts, opts);
    if (opts->verbose) { // Reprint every host result at the end
        for (unsigned int i = 0; i < ft_vector_size(vec_hosts); i++)
            print_host_result(&vec_hosts[i], opts);
    }
    hosts_free(&vec_hosts);
    return (ret);
}