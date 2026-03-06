#include <errno.h>
#include <error.h>
#include <memory.h>
#include <nmap.h>
#include <string.h>

struct host *hosts_create(char **args, unsigned int nbr_args, t_options *opts);
void hosts_free(struct host **hosts);

void free_services_vec(struct service *vec_services);

void print_host_result(struct host *host, t_options *opts);
void print_scan_result(struct scan_result *result, struct host *host,
                       t_options *opts);
void print_task_result(struct task_handle *task);
void print_task(struct task_handle *task);
void print_worker(struct worker_handle *worker);
;

void *worker_routine(void *data);

void update_host_rtt(struct host_stats *stat, float rtt);

void user_input(struct host *vec_hosts,
                struct worker_handle workers_pool[MAX_WORKER], t_options *opts);

int dns_init(struct task_handle *data);
int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data, struct pollfd sock);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);
int tcp_packet_send(struct task_handle *data);
int tcp_packet_rcv(struct task_handle *data, struct pollfd sock);
int tcp_init(struct task_handle *data);
int tcp_packet_timeout(struct task_handle *data);
int tcp_release(struct task_handle *data);

struct host *check_double_host(struct host *vec_hosts, struct host *host);

/// Cmp function to sort port vector
static int cmp(void *a, void *b) {
    if (((struct port_info *)a)->port < ((struct port_info *)b)->port)
        return (-1);
    else
        return (1);
}

static struct port_info *assign_multiple_port(uint16_t *nbr_port,
                                              struct scan_result *scan) {
    uint16_t nbr = 0, i = 0;
    for (; i < scan->nbr_port && nbr < MAX_PORT_TASK; i++) {
        if (scan->ports[i].state !=
            PORT_UNKNOWN) { // @warning: ATOMIC OPERATION
            if (nbr == 0)
                continue;
            break;
        }
        nbr++;
    }
    *nbr_port = nbr;
    if (*nbr_port == 0)
        error(1, errno,
              "fatal: trying to assign port from a scan with no port "
              "pending scan");
    // Sort to optimize port iteration in task
    if (ft_merge_sort(scan->ports + (i - nbr), nbr, cmp, false))
        error(-1, errno, "sorting port vector");
    return (scan->ports + (i - nbr));
}

/// @brief
/// @param vec_hosts
/// @param skip_blocking If enable, blocking scan will not be considered as
/// candidate
/// @return
static struct host *find_available_host(struct host *vec_hosts,
                                        bool skip_blocking) {

    const size_t vec_size = ft_vector_size(vec_hosts);
    struct host *host;
    // struct scan_result *udp_scan;

    for (unsigned int i = 0; i < vec_size; i++) {
        host = &vec_hosts[i];
        switch (host->state) {
        case STATE_PENDING_RESOLVE:
            if (skip_blocking)
                continue;
            return (host);
        case STATE_PING_PENDING:
            return (host);

        case STATE_SCAN_PENDING:
            return (host);

        case STATE_SCAN_RUNNING: // An host may perform simultaneous UDP and TCP
                                 // scan
            if (host->current_scan.udp == 0 &&
                host->scans[SCAN_UDP].state == SCAN_PENDING)
                return (host);
            if ((host->current_scan.int_representation & SCAN_LIST_TCP_MASK) ==
                    0 &&
                (host->scans[SCAN_SYN].state == SCAN_PENDING ||
                 host->scans[SCAN_ACK].state == SCAN_PENDING ||
                 host->scans[SCAN_NULL].state == SCAN_PENDING ||
                 host->scans[SCAN_FIN].state == SCAN_PENDING ||
                 host->scans[SCAN_XMAS].state == SCAN_PENDING))
                return (host);

        default: // For now DNS and ping only
            continue;
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
    struct scan_result *scan = &host->scans[task->scan_type];

    host->current_scan.int_representation |= (1 << task->scan_type);
    scan->state = SCAN_RUNNING;
    scan->assigned_worker += 1;
    switch (task->scan_type) {
    case SCAN_DNS:
        host->state = STATE_RESOLVING;
        break;
    case SCAN_PING:
        host->state = STATE_PING_SENT;
        task->io_data.ping.rslt->state = PORT_SCANNING;
        break;
    case SCAN_SYN:
    case SCAN_ACK:
    case SCAN_NULL:
    case SCAN_FIN:
    case SCAN_XMAS:
        for (uint16_t i = 0; i < task->io_data.tcp.nbr_port; i++) {
            task->io_data.tcp.ports[i].state = PORT_SCANNING;
        }
        scan->remaining -= task->io_data.tcp.nbr_port;
        host->state = STATE_SCAN_RUNNING;
        break;

    default:
        host->state = STATE_SCAN_RUNNING;
        scan->assigned_worker += 1;
        // scan->break;
    }
}

/// @brief Host must be assign to task before calling this function
/// @param scan
/// @param task
/// @param nbr_socket
/// @param opts
static void assign_task_scan(struct scan_result *scan, struct task_handle *task,
                             unsigned int *nbr_socket, t_options *opts) {
    (void)opts;
    float ftimeout = task->host->stats.mean_rtt * opts->rtt_timeout;
    struct timeval timeout;
    timeout.tv_sec = (time_t)(ftimeout / 1000.f);
    timeout.tv_usec =
        (time_t)((ftimeout - ((float)timeout.tv_sec * 1000.f)) * 1000.f);

    task->scan_type = scan->type;
    task->error = &scan->error;
    switch (task->scan_type) {
    case SCAN_SYN:
    case SCAN_ACK:
    case SCAN_NULL:
    case SCAN_FIN:
    case SCAN_XMAS:
        task->io_data.tcp.ports =
            assign_multiple_port(&task->io_data.tcp.nbr_port, scan);
        task->init = tcp_init;
        task->packet_send = tcp_packet_send;
        task->packet_rcv = tcp_packet_rcv;
        task->packet_timeout = tcp_packet_timeout;
        task->release = tcp_release;
        task->timeout = task->base_timeout = timeout;
        task->io_data.tcp.daddr = task->host->addr.sin_addr;
        task->io_data.ping.saddr = (struct sockaddr_in){0};
        *nbr_socket += 1;
        task->sock_eph.fd = -1;
        task->sock_icmp = (struct sock_instance){.fd = -1};
        task->sock_main = (struct sock_instance){.fd = -1};
        break;

    case SCAN_CONNECT:
        break;

    case SCAN_UDP:
        break;
    default:
        break;
    }
}

/// @brief Fill ```task``` with an available task in ```host``` and update
/// ```host``` status
/// @param host
/// @param task
/// @param nbr_socket used to increment the number of sockets the worker has to
/// manage. Blocking task  (```SCAN_DNS``` and ```SCAN_CONNECT```) will be
/// rejected if nbr_socket > 0
/// @return ```false``` if no available task
static bool assign_task(struct host *host, struct task_handle *task,
                        unsigned int *nbr_socket, t_options *opts) {
    bool ret = false;
    // Only relevant to print debug message when task is started
    bool scan_started = false;
    bool skip_blocking = *nbr_socket > 0;
    uint16_t available_port;
    struct scan_result *scan;

    task->opts = opts;
    switch (host->state) {
    case STATE_PENDING_RESOLVE:
        task->scan_type = SCAN_DNS;
        task->init = dns_init;
        task->packet_rcv = NULL;
        task->packet_timeout = NULL;
        task->release = NULL;
        task->packet_send = NULL;
        task->timeout = task->base_timeout = (struct timeval){0};
        task->io_data.dns.hostname_rslv = NULL;
        task->io_data.dns.addr = (struct sockaddr_in){0};
        task->io_data.dns.hostname = host->hostname;
        task->io_data.dns.dont_resolve = (opts->numeric ? true : false);
        task->error = &host->scans[SCAN_DNS].error;
        task->host = host;
        ret = true;
        scan_started = true;
        break;

    case STATE_PING_PENDING:
        available_port =
            host->scans[SCAN_PING].nbr_port - host->scans[SCAN_PING].remaining;
        task->scan_type = SCAN_PING;
        task->init = ping_init;
        task->packet_send = ping_packet_send;
        task->packet_rcv = ping_packet_rcv;
        task->packet_timeout = ping_packet_timeout;
        task->release = ping_release;
        task->timeout = task->base_timeout =
            (struct timeval){.tv_sec = PING_TIMEOUT, .tv_usec = 0};
        task->io_data.ping.daddr = host->addr.sin_addr;
        task->io_data.ping.rslt = &host->scans[SCAN_PING].ports[available_port];
        task->error = &host->scans[SCAN_PING].ports[available_port].error;
        task->io_data.ping.saddr = (struct sockaddr_in){0};
        *nbr_socket += 2;
        task->sock_eph.fd = -1;
        task->sock_icmp = (struct sock_instance){.fd = -1};
        task->sock_main = (struct sock_instance){.fd = -1};
        task->host = host;
        ret = true;
        if (host->scans[SCAN_PING].remaining == host->scans[SCAN_PING].nbr_port)
            scan_started = true;
        break;

    case STATE_SCAN_RUNNING:
    case STATE_SCAN_PENDING:
        for (unsigned int i = SCAN_PING + 1; i < SCAN_NBR; i++) {
            scan = &host->scans[i];
            if (scan->state != SCAN_PENDING)
                continue;
            if (scan->type == SCAN_CONNECT &&
                host->current_scan.int_representation != 0)
                continue;
            ret = true;
            if (scan->remaining == scan->nbr_port)
                scan_started = true;
            task->host = host;
            assign_task_scan(scan, task, nbr_socket, opts);
            break;
        }
        if (ret == false) // Unlikely
            error(1, errno,
                  "fatal: an host is in scan_pending state but does not have "
                  "any scan pending");
        break;

    default:
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
    uint16_t available_port;
    bool ret;
    struct port_info *port;

    scan = &task.host->scans[task.scan_type];
    if (--scan->assigned_worker == 0) {
        task.host->current_scan.int_representation &= ~(1 << scan->type);
    }
    switch (scan->type) {
    case SCAN_DNS: // Should not happen
        scan->state = SCAN_PENDING;
        task.host->state = STATE_PENDING_RESOLVE;
        break;
    case SCAN_PING:
        available_port = scan->nbr_port - scan->remaining;
        if (++scan->ports[available_port].retries >= MAX_RETRIES) {
            if (--scan->remaining == 0) {
                scan->state = SCAN_DONE;
                scan->ports->reason.type = REASON_ERROR;
                task.host->state = STATE_ERROR;
            }
            break;
        }
        scan->state = SCAN_PENDING;
        task.host->state = STATE_PING_PENDING;
        break;
    case SCAN_SYN:
    case SCAN_ACK:
    case SCAN_NULL:
    case SCAN_FIN:
    case SCAN_XMAS:
        for (uint16_t i = 0; i < task.io_data.tcp.nbr_port; i++) {
            port = &task.io_data.tcp.ports[i];
            if (++port->retries >= MAX_RETRIES) {
                port->state = PORT_ERROR;
                port->reason.type = REASON_ERROR;
            } else {
                port->state = PORT_UNKNOWN;
                scan->remaining++;
            }
        }
        if (scan->remaining == 0 && scan->assigned_worker == 0)
            scan->state = SCAN_DONE;
        else
            scan->state = SCAN_PENDING;
        break;

    default:

        if (--scan->assigned_worker == 0) {
            task.host->current_scan.ping = 0;
        }
        break;
    }
    ret = switch_state(task.host);
    if (scan->state == SCAN_DONE && opts->verbose > 0) {
        printf("Scan done, host %s\n", task.host->hostname);
        print_scan_result(scan, task.host, opts);
    }
    if (ret && opts->verbose)
        print_host_result(task.host, opts);
    // if (task.host->state != STATE_ERROR && *task.error) {
    //     free(*task.error);
    //     *task.error = NULL;
    // }
    // if (task.host->state == STATE_ERROR)
    //     print_host_result(task.host, opts);
}

static void handle_task_done(struct task_handle task, struct host *vec_hosts,
                             t_options *opts) {
    struct scan_result *scan;
    uint16_t available_port;
    bool ret;

    // if ((task.flags.error == 1 && opts->verbose > 0) || opts->verbose >
    // 1)
    //     print_task_result(&task);
    scan = &task.host->scans[task.scan_type];
    if (--scan->assigned_worker == 0) {
        task.host->current_scan.int_representation &= ~(1 << scan->type);
    }
    switch (scan->type) {
    case SCAN_DNS:
        task.host->hostname_rsvl = task.io_data.dns.hostname_rslv;
        task.host->addr = task.io_data.dns.addr;
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
        available_port = scan->nbr_port - scan->remaining;
        if (*task.error && (*task.error)->type == NMAP_ERROR_WORKER) {
            scan->ports[available_port].reason.type = REASON_ERROR;
        }
        scan->remaining--;
        switch (scan->ports[available_port].reason.type) {
        case REASON_NO_RESPONSE:
            task.host->state = STATE_PING_TIMEOUT;
            break;

        case REASON_ICMP_REPLY:
        case REASON_RST:
        case REASON_SYN_ACK:
            task.host->state = STATE_UP;
            update_host_rtt(&task.host->stats,
                            scan->ports[available_port].reason.rtt);
            break;

        case REASON_USER_INPUT:
            task.host->state = STATE_UP;
            update_host_rtt(&task.host->stats, DFT_PORT_TIMEOUT);
            break;

        case REASON_HOST_UNREACH:
        case REASON_PORT_UNREACH:
        case REASON_TIME_EXCEEDED:
            task.host->state = STATE_DOWN;
            break;

        case REASON_ERROR:
        default: // UNEXPECTED REASON
            task.host->state = STATE_ERROR;
            break;
        }
        if (task.host->state != STATE_UP && scan->remaining > 0) {
            task.host->state = STATE_PING_PENDING;
            scan->state = SCAN_PENDING;
        } else
            scan->state = SCAN_DONE;
        break;

    case SCAN_SYN:
    case SCAN_ACK:
    case SCAN_NULL:
    case SCAN_FIN:
    case SCAN_XMAS:
        for (uint16_t i = 0; i < task.io_data.tcp.nbr_port; i++) {
            if (task.io_data.tcp.ports[i].reason.rtt <= 0.f)
                continue;
            update_host_rtt(&task.host->stats,
                            task.io_data.tcp.ports[i].reason.rtt);
        }
        // if (*task.error && ((*task.error)->type == NMAP_ERROR_WORKER)) {
        if (*task.error) {
            for (uint16_t i = 0; i < task.io_data.tcp.nbr_port; i++) {
                if (task.io_data.tcp.ports[i].state != PORT_SCANNING)
                    continue;
                task.io_data.tcp.ports[i].state = PORT_ERROR;
                task.io_data.tcp.ports[i].reason.type = REASON_ERROR;
            }
        }
        if (scan->remaining == 0 && scan->assigned_worker == 0)
            scan->state = SCAN_DONE;
        else
            scan->state = SCAN_PENDING;
        break;
    default:
        break;
    }
    ret = switch_state(task.host);
    if (scan->state == SCAN_DONE && opts->verbose > 0) {
        printf("Scan done, host %s\n", task.host->hostname);
        print_scan_result(scan, task.host, opts);
    }
    if (ret && opts->verbose)
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

/// @brief Check if any worker wants to join, if so, handle every task it
/// had and update host status
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
        handle_worker_result(&workers_pool[i], ret, vec_hosts, opts);
        ft_vector_free((t_vector **)&workers_pool[i].tasks_vec);
        workers_pool[i].state = WORKER_AVAILABLE;
        workers_pool[i].nbr_sock = 0;
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
        printf("Cancelling worker (from main thread)...\n");
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
/// initialisation failure or no available task, else ```address``` of
/// allocated worker in vector
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
        host = find_available_host(hosts_vec, true);
        if (task.scan_type == SCAN_DNS || task.scan_type == SCAN_CONNECT) {
            ret = false; // blocking task be executed by a dedicated worker
        }
        // Adds task to worker
        ft_vector_push((t_vector **)&worker->tasks_vec, &task);
    } while (ret == true && host &&
             ft_vector_size(worker->tasks_vec) < MAX_TASK_WORKER);
    if (ft_vector_resize((t_vector **)&worker->tasks_vec,
                         ft_vector_size(worker->tasks_vec))) {
        cancel_worker(worker, opts);
        return (NULL);
    }
    worker->state = WORKER_RUNNING;
    worker->opts = opts;
    if (pthread_create(&worker->tid, NULL, worker_routine, worker)) {
        cancel_worker(worker, opts);
        return (NULL);
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

uint16_t *parse_ports(const char *ports);

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
    opts->port_vec = parse_ports(opts->ports);
    vec_hosts = hosts_create(args, nbr_args, opts);
    ret = main_loop(vec_hosts, opts);
    if (opts->verbose == 0) { // Reprint every host result at the end
        for (unsigned int i = 0; i < ft_vector_size(vec_hosts); i++)
            print_host_result(&vec_hosts[i], opts);
    }
    hosts_free(&vec_hosts);
    free_services_vec(opts->services_vec);
    ft_vector_free((t_vector **)&opts->port_vec);
    return (ret);
}