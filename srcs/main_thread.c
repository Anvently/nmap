#include <errno.h>
#include <error.h>
#include <memory.h>
#include <nmap.h>
#include <string.h>

struct host *hosts_create(char **args, unsigned int nbr_args, t_options *opts);
void hosts_free(struct host **hosts);

void print_host_result(struct host *host, t_options *opts);
void print_scan_result(struct scan_result *result, t_options *opts);
void print_task_result(struct task_handle *task);

void *worker_routine(void *data);

void user_input(struct host *vec_hosts, struct worker_handle *vec_workers,
                t_options *opts);

static struct host *find_available_host(struct host *vec_hosts) {

    const size_t vec_size = ft_vector_size(vec_hosts);
    // struct scan_result *udp_scan;

    for (unsigned int i = 0; i < vec_size; i++) {
        switch (vec_hosts[i].state) {
        case STATE_PENDING_RESOLVE:
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
    case STATE_DOUBLOON:
    case STATE_ERROR:
    case STATE_DOWN:
    case STATE_PING_TIMEOUT:
    case STATE_RESOLVE_FAILED:
    case STATE_SCAN_DONE:
        return (1);

    case STATE_PENDING_RESOLVE:
    case STATE_PING_PENDING:
    case STATE_SCAN_PENDING:
        return (0);

    case STATE_RESOLVING:
        if (host->scans[SCAN_DNS].error)
            host->state = STATE_RESOLVE_FAILED;
        else
            host->state = STATE_RESOLVED;
        return (switch_state(host));

    case STATE_RESOLVED:
        if (host->scans[SCAN_PING].state == SCAN_PENDING)
            host->state = STATE_PING_PENDING;
        else
            host->state = STATE_UP;
        return (switch_state(host));

    case STATE_PING_SENT:
        switch (host->scans[SCAN_PING].ports[0].reason.type) {
        case REASON_NO_RESPONSE:
            host->state = STATE_PING_TIMEOUT;
            break;

        case REASON_HOST_UNREACH:
            host->state = STATE_DOWN;
            break;

        default:
            host->state = STATE_UP;
        }
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

int dns_packet_send(struct task_handle *data);
int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

/// @brief Fill ```task``` with an available task in ```host```
/// @param host
/// @param task
/// @return ```false``` if no available task
static bool assign_task(struct host *host, struct task_handle *task) {
    switch (host->state) {
    case STATE_PENDING_RESOLVE:
        task->scan_type = SCAN_DNS;
        task->init = NULL;
        task->packet_rcv = NULL;
        task->packet_timeout = NULL;
        task->release = NULL;
        task->packet_send = dns_packet_send;
        task->timeout = (struct timeval){0};
        task->data.dns.hostname_rslv = NULL;
        task->data.dns.addr = (struct sockaddr_in){0};
        task->data.dns.hostname = host->hostname;
        task->host = host;
        return (true);

    case STATE_PING_PENDING:
        task->scan_type = SCAN_PING;
        task->init = ping_init;
        task->packet_send = ping_packet_send;
        task->packet_rcv = ping_packet_rcv;
        task->packet_timeout = ping_packet_timeout;
        task->release = ping_release;
        task->timeout = (struct timeval){.tv_sec = PING_TIMEOUT, .tv_usec = 0};
        task->data.ping.daddr = host->addr.sin_addr;
        task->data.ping.rslt = &host->scans[SCAN_PING].ports[80];
        task->data.ping.saddr = (struct sockaddr_in){0};
        task->data.ping.sock_eph = -1;
        task->data.ping.sock_icmp = -1;
        task->data.ping.sock_tcp = -1;
        task->host = host;
        return (true);

    default: // For now DNS and PING only

        return (false);
    }
}

/// @brief Must be called once task initialization succeed and worker thread was
/// launched. Host status will be be updated.
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

static void handle_worker_result(struct worker_handle *worker, void *ret,
                                 t_options *opts) {
    (void)ret;
    struct task_handle task;
    struct scan_result *scan;

    unsigned int i = ft_vector_size(worker->tasks_vec);
    while (i--) {
        task = worker->tasks_vec[i];
        scan = &task.host->scans[task.scan_type];
        scan->assigned_worker--;
        if (scan->assigned_worker == 0) { // UDP scan may not fall through
            scan->state = SCAN_DONE;
            if (scan->remaining > 0)
                scan->state = SCAN_PENDING;
            else { // Scan done
                if (opts->verbose > 0) {
                    fprintf(stdout, "Results for host %s\n",
                            task.host->hostname);
                    print_scan_result(scan, opts);
                }
            }
        }
        if (scan->state != SCAN_RUNNING) {
            task.host->current_scan.int_representation &= ~(1 << scan->type);
        }
        if (scan->type == SCAN_DNS) {
            task.host->addr = task.data.dns.addr;
            task.host->hostname_rsvl = task.data.dns.hostname_rslv;
        }
        if (switch_state(task.host))
            print_host_result(task.host, opts);
        if ((task.error && opts->verbose > 0) || opts->verbose > 1)
            print_task_result(&task);
    }
}

/// @brief Check if any worker wants to join, if so, handle every task it had
/// and update host status
/// @param workers_vec
/// @param opts
static void loop_worker_state(struct worker_handle *workers_vec,
                              t_options *opts) {
    void *ret;
    size_t i = ft_vector_size(workers_vec);
    while (i--) {
        if (workers_vec[i].state != WORKER_DONE)
            continue;
        if (pthread_join(workers_vec[i].tid, &ret))
            error(-1, errno, "joining thread");
        handle_worker_result(&workers_vec[i], ret, opts);
        ft_vector_free((t_vector **)&workers_vec->tasks_vec);
        ft_vector_erase((t_vector **)&workers_vec,
                        i); // No reallocation possible
    }
}

/// @brief Initialize, allocate and run worker
/// @return ```NULL``` if no worker could be allocated, because of task
/// initialisation failure or no available task, else ```address``` of allocated
/// worker in vector
static struct worker_handle *init_worker(struct host *hosts_vec,
                                         struct worker_handle *workers_vec) {
    struct worker_handle worker = {0}, *worker_addr;
    struct task_handle task;
    struct host *host;
    bool ret;

    host = find_available_host(hosts_vec);
    if (host == NULL)
        return (NULL);
    worker.tasks_vec =
        ft_vector_create(sizeof(struct task_handle), MAX_TASK_WORKER);
    do {
        task = (struct task_handle){0};
        ret = assign_task(host, &task);
        if (ret == false) { // This host has no more task
            host = find_available_host(hosts_vec);
            if (host)
                ret = true;
            continue;
        }
        if (task.scan_type == SCAN_DNS) {
            if (ft_vector_size(worker.tasks_vec) >
                0) // ignore dns task if it will block another task
                continue;
            ret = false; // DNS task will be executed by a dedicated worker
        }
        if (task.init && task.init(&task))
            break;
        // Adds task to worker
        ft_vector_push((t_vector **)&worker.tasks_vec, &task);
        confirm_task(&task); // Update host status

    } while (ret == true && ft_vector_size(worker.tasks_vec) < MAX_TASK_WORKER);
    if (ft_vector_resize((t_vector **)&worker.tasks_vec,
                         ft_vector_size(worker.tasks_vec)))
        // Task were confirmed so we cant just return
        error(-1, errno, "failed to shrink task vectors");

    ft_vector_push((t_vector **)&workers_vec, &worker);
    worker_addr = &workers_vec[ft_vector_size(workers_vec) - 1];
    if (pthread_create(&worker_addr->tid, NULL, worker_routine, worker_addr))
        error(-1, errno, "failed to create worker thread");
    return (worker_addr);
}

static int main_loop(struct host *vec_hosts, t_options *opts) {
    unsigned int nbr_workers;
    struct worker_handle *workers_vec =
        ft_vector_create(sizeof(struct worker_handle), MAX_WORKER);

    if (workers_vec == NULL)
        error(-1, errno, "allocating workers vector");
    // Disable vector shrinking to prevent any reallocation
    ft_vector_set_shrink(workers_vec, false);
    while (1) {
        user_input(vec_hosts, workers_vec, opts);
        usleep(1000); // 1ms sleep
        loop_worker_state(workers_vec, opts);
        // If all state done, break_loop
        if (check_hosts_done(vec_hosts) == true)
            break;
        // Find available host
        nbr_workers = ft_vector_size(workers_vec);
        if (nbr_workers >= MAX_WORKER)
            continue;
        init_worker(vec_hosts, workers_vec);
    }
    ft_vector_free((t_vector **)&workers_vec);
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