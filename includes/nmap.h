#include <libft.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#ifndef NMAP_H
#define NMAP_H

#define PING_TIMEOUT 5 // Default ping timeout
#define MAX_WORKER 250 // Maximum number of threads
// Maximum number of task a worker can take (only UDP scan is able to scan
// multiple port of a same host)
#define MAX_TASK_WORKER 16
#define MAX_PORT_NBR 1024U // Maximum different port nmap is allowed to scan
#define MAX_RETRIES 3

// It's the task responspability (in send handler to override this default
// timeout)
#define DFT_TASK_TIMEOUT 3

#define TCP_DFT_TOS (IPTOS_DSCP_AF31 | IPTOS_ECN_ECT0)
#define UDP_DFT_TOS (IPTOS_CLASS_CS0)
#define ICMP_DFT_TOS (IPTOS_DSCP_AF31)

enum OPTIONS {
    OPT_VERBOSE = 0,    //-v Verbose output. Do not suppress DUP replies when
                        // pinging multicast address
    OPT_HELP,           // -h, --help
    OPT_SIZE,           // -s, --size
    OPT_NUMERIC,        // -n, --numeric
    OPT_INTERFACE,      // -e, --interface
    OPT_PATTERN,        // --data
    OPT_TTL,            // -ttl
    OPT_SEQUENTIAL,     // -r, --sequential
    OPT_FRAGMENT,       // -f, --mtu
    OPT_USURP,          // -S, --usurp
    OPT_REASON,         // --reason
    OPT_LIST,           // -L, --list
    OPT_SKIP_DISCOVERY, // --skip-ping
    OPT_SRC_PORT,       // -g, --source-port
    OPT_OPEN,           // --open
    OPT_ALL,            // --all
    // CUSTOMs
    OPT_PORT,    // -p, --port
    OPT_THREADS, // -t, --threads (0 à 250)
    OPT_SCAN,    // -s, --scan
    OPT_FILE,    // --file
    OPT_NBR,     //
};

union scan_list {
    struct {
        uint16_t dns : 1;
        uint16_t ping : 1;
        uint16_t syn : 1;
        uint16_t ack : 1;
        uint16_t null : 1;
        uint16_t fin : 1;
        uint16_t xmas : 1;
        uint16_t connect : 1;
        uint16_t udp : 1;
        uint16_t raw_udp
            : 1; // if usurp option is enabled, we need raw socket the
                 // IP_HDRINCL option enabled, then limitation is 1 host/socket
    };
    uint16_t int_representation;
} __attribute__((__packed__));

/// @brief ```t_options``` typedef is already defined as an alias for this
/// struct in libft
struct s_options {
    unsigned int verbose;
    bool help;
    unsigned int size;
    bool numeric;
    bool resolve;
    const char *interface;
    const char *pattern;
    uint8_t ttl;
    bool sequential;
    uint16_t mtu;
    struct {
        const char *arg;
        struct in_addr addr;
    } usurp;
    bool reason;
    bool list;
    bool skip_discovery;
    uint16_t src_port;
    bool open;
    bool all;
    const char *ports;
    uint16_t threads;
    union scan_list enabled_scan; // 1 scan = 1 bit
    const char *file;
};

enum host_state {
    STATE_DOUBLOON = 0, // Host was inputed twice
    STATE_ERROR,        // Error received

    STATE_PENDING_RESOLVE, // Was inputed by user // No worker assigned

    // blocking
    // DNS
    STATE_RESOLVING,      // Dns resolution pending
    STATE_RESOLVED,       // Dns resolution done
    STATE_RESOLVE_FAILED, // Dns resolution failed

    // Ping
    STATE_PING_PENDING, // Need to send a ping
    STATE_PING_SENT,    // Waiting for ping response
    STATE_PING_TIMEOUT, // No response after timeout
    STATE_DOWN,         // Ping failed (host unreachable)
    STATE_UP,           // Ping sucedeed

    // Scan
    STATE_SCAN_PENDING, // No scan
    STATE_SCAN_RUNNING, // A scan is in progress
    STATE_SCAN_DONE,    // All required scan are done
} __attribute__((__packed__));

enum scan_state {
    SCAN_DISABLE = 0,
    SCAN_PENDING,
    SCAN_RUNNING,
    SCAN_DONE,
} __attribute__((__packed__));

enum scan_type {
    SCAN_DNS = 0,
    SCAN_PING,
    SCAN_SYN,
    SCAN_ACK,
    SCAN_NULL,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_CONNECT,
    SCAN_UDP,
    SCAN_NBR,
    SCAN_RAW_UDP // Doesn't really count as a different scan from udp
} __attribute__((__packed__));

enum port_state {
    PORT_UNKNOWN = 0, // Pending scan
    PORT_SCANNING,    // A worker is currently scanning this port
    PORT_OPENED,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNFILTERED,
    PORT_OPEN_FILTERED,
    PORT_CLOSED_FILTERED
} __attribute__((__packed__));

enum result_reason {
    REASON_UNKNOWN = 0,
    REASON_ICMP_REPLY,
    REASON_SYN_ACK,
    REASON_RST,
    REASON_PORT_UNREACH,
    REASON_HOST_UNREACH,
    REASON_CONN_REFUSED,
    REASON_USER_INPUT,
    REASON_NO_RESPONSE,
    REASON_ERROR
} __attribute__((__packed__));

struct port_info {
    uint16_t port;                 // 1-65535
    _Atomic enum port_state state; // !!! Atomic operation only !!!
    struct {
        uint8_t ttl;
        enum result_reason type;
    } reason;
    struct nmap_error *error; // Error related to a single port
    uint8_t retries;          // Number of time the task is retried
} __attribute__((__packed__));

struct scan_result {
    enum scan_type type;
    enum scan_state state;

    // Number of remaining port to be scanned.
    // An unemployed worker can directly choose the port `ports[remaining - 1]`,
    // and decrement remaining
    uint16_t remaining;
    uint16_t assigned_worker; // Number of worker assign to this scan

    uint16_t nbr_port;
    // Allocated array, (randomized) ports, the main thread can only
    // access these element when the scan is done.
    // DNS scan has no port_info associated (ports = NULL).
    // Ping scan has a single port_info associated
    // Port scans have one port_info struct per port scanned.
    struct port_info *ports;
    // Error related to host (for ping or DNS scan for example)
    struct nmap_error *error;
};

struct host {
    struct sockaddr_in addr;
    char *hostname_rsvl; // FQDN - resolved host with getnameinfo()
    const char *hostname;
    enum host_state state;
    struct scan_result scans[SCAN_NBR];
    union scan_list current_scan;
};

struct dns_data {
    const char *hostname;
    struct sockaddr_in addr;
    // Allocated by worker, copied and freed by main thread
    char *hostname_rslv;
    bool dont_resolve;
};

struct ping_data {
    struct in_addr daddr;     // peer address
    struct sockaddr_in saddr; // tcp
    struct port_info *rslt;
};

struct tcp_data {           // Used by SYN, ACK, NULL, XMAS, FIN
    uint8_t flag;           // TCP flag to send ()
    struct port_info *port; // result
};

struct connect_data {
    struct in_addr daddr; // peer address
    struct port_info *port;
};

struct udp_data {
    struct in_addr daddr; // peer address
    struct port_info *port;
};

union task_data {
    struct dns_data dns;
    struct ping_data ping;
    struct tcp_data tcp;
    struct connect_data connect;
    struct udp_data udp;
};

struct sock_instance {
    int fd;
    struct pollfd *pollfd;
};
struct task_handle {
    // Pointer toward rslt data. No race condition if assigned by host

    enum scan_type scan_type;

    union task_data io_data; // Data filled by main_thread
    struct timeval timeout;
    struct host *host; // Host associated to the task

    void *ctx; // worker allocated data

    struct {
        int fd;
    } sock_eph;                     // mock socket to lock an ephemeral port
    struct sock_instance sock_main; // tcp/udp raw socket
    struct sock_instance sock_icmp; // icmp socket

    // WORKER : Called at beginning of task
    // Initialized flag is set by worker if success (0 returned).
    // Done flag is set by worker if error (non-zero returned), but release IS
    // NOT CALLED.
    /// It's the scan responsability to set or not the error flag.
    // A scan should not send the first data packet in init(), but should rather
    // use packet_send for this
    int (*init)(struct task_handle *data);

    // WORKER : Called when send_state is disabled
    // If non-zero returned, task is released.
    // Packet send will be called as long as the send_state is disabled.
    // The scan should set an appropriate timeout and enable send_state.
    // If non-zero returned, task is released (but no error is set)
    int (*packet_send)(struct task_handle *data);

    // WORKER : Called when main_rcv or icmp_rcv is toggled
    ///
    // If non-zero returned, task is released (but no error is set).
    // If the scan wants to answer something, it may choose to send its packet
    // in packet_rcv or set the send_state (with a possibly short timeout) and
    // wait for the next loop to send the reply.
    ///
    // @warning: if a scan use 2 socket, this handler could be called twice in a
    // single event loop, so if the send_state is changed during the first call,
    // the second call may see an unexpected send_state
    ///
    // Expected flag in sock_instance->pollfd.events are POLLIN, POLLHUP and
    // POLLERR
    int (*packet_rcv)(struct task_handle *data, struct sock_instance *sock);

    // WORKER : Called when timeout is toggled
    // timeout flags is set by worker but can be restaured (timeout must
    // also be reset). If non-zero returned, task is released. If zero returned,
    // send_state is resetted (but not timeout flag).
    /// For retry routine, its better to have the task failed and
    // to let the main thread handle the max_retry variable
    int (*packet_timeout)(struct task_handle *data);

    // WORKER : Called when done or cancelled is toggled.
    // Worker will disable initialized flag and will enable the done flag
    int (*release)(struct task_handle *data);

    struct {
        uint8_t initialized : 1; // Data were initialized, when calling release,
                                 // flag is set to 0
        uint8_t send_state : 1;  // 0 => nothing sent, 1 => something sent
                                 // (waiting for related response)
        uint8_t main_rcv : 1;    // incoming tcp/udp packet
        uint8_t icmp_rcv : 1;    // incoming icmp (for ping only)
        uint8_t timeout : 1;     // Timeout has been reached
        uint8_t done : 1;        // Scan complete
        uint8_t error : 1; // Error, ex: syscall error, task will not reassigned
        uint8_t cancelled : 1; // The task failed to launch as it should, it
                               // will be later reassigned
    } flags;
    struct nmap_error **error; // Ptr where errors must be registered
    t_options *opts;
};

struct worker_handle {             // 1 worker = 1 thread = 1 polling
    struct task_handle *tasks_vec; // Allocated vector of task
    _Atomic enum {
        WORKER_AVAILABLE = 0,
        WORKER_RUNNING,
        WORKER_DONE
    } state;               // !!! atomic access only !!!
    unsigned int nbr_sock; // usefull for polling structure
    pthread_t tid;
};

enum nmap_error_type {
    NMAP_ERROR_DNS,    // Error related to DNS failure, likely
    NMAP_ERROR_SYS,    // Error related to system call failure, unlikely
    NMAP_ERROR_PING,   // Error related to ping procedure
    NMAP_ERROR_SCAN,   // Undefined
    NMAP_ERROR_WORKER, // Error related to deadlock condition or unexpected
                       // behaviour, mostly for debugging
};

struct nmap_error {
    int error; // errno number
    enum nmap_error_type type;
    union { // Examples
        struct {
            char func_fail[16];
            char description[64];
        } dns;
        struct {
            char func_fail[16];
            char description[64];
        } sys;
        struct {
            char func_fail[16];
            char description[64];
            struct icmphdr icmphdr;
            uint8_t detail[8];
        } ping;
        struct {

        } scan;
    } u;
};

int ft_nmap(char **args, unsigned int nbr_args, t_options *opts);

#endif