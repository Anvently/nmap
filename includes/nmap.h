#include <libft.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdint.h>
#include <sys/time.h>

#ifndef NMAP_H
#define NMAP_H

enum OPTIONS {
    OPT_VERBOSE = 0, //-v Verbose output. Do not suppress DUP replies when
                     // pinging multicast address
    OPT_HELP,        // -h
    OPT_SIZE,        // -s
    OPT_NUMERIC,     // -n
    OPT_INTERFACE,   // -e
    OPT_RESOLVE,     // -R
    OPT_TTL,         // -ttl
    OPT_SEQUENTIAL,  // -, --sequential
    OPT_FRAGMENT,    // -f, --mtu
    OPT_USURP,       // -S, --usurp
    OPT_PATTERN,     // --data
    OPT_REASON,      // --reason
    // CUSTOMs
    OPT_PORTS,   // -p, --port
    OPT_IP,      // --ip
    OPT_THREADS, // -t, --threads (0 à 250)
    OPT_SCAN,    // -s, --scan
    OPT_FILE,    // --file
    OPT_NBR,     //
};

// TO ADD
/*
--open


*/

/// @brief ```t_options``` typedef is already defined as an alias for this
/// struct in libft
struct s_options {
    bool help;
    bool verbose;
    unsigned int size;
    unsigned int timeout;
    unsigned int linger_timeout;
    const char *pattern;
    unsigned int identifier;
    uint8_t tos;
    uint8_t ttl;
    bool numeric;
    bool ignore_routing;
    float interval;
    bool flood;
    unsigned int preload;
};

#define PING_TIMEOUT 5
#define MAX_WORKER 250 // Maximum number of threads
// Maximum number of task a worker can take (only UDP scan is able to scan
// multiple port of a same host)
#define MAX_TASK_WORKER 16

enum host_state {
    STATE_ERROR = -2, // Error received
    STATE_DOWN = -1,  // Ping failed (host unreachable)

    STATE_PENDING_RESOLVE = 0, // Was inputed by user // No worker assigned

    // blocking
    // DNS
    STATE_RESOLVING,      // Dns resolution pending
    STATE_RESOLVED,       // Dns resolution done
    STATE_RESOLVE_FAILED, // Dns resolution failed

    // Ping
    STATE_PING_PENDING, // Need to send a ping
    STATE_PING_SENT,    // Waiting for ping response
    STATE_PING_TIMEOUT, // No response after timeout
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
    SCAN_UDP,
    SCAN_CONNECT,
    SCAN_NBR
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
    REASON_SYN_ACK,
    REASON_RST,
    REASON_PORT_UNREACH,
    REASON_CONN_REFUSED,
    REASON_NO_RESPONSE,
} __attribute__((__packed__));

struct port_info {
    uint16_t port; // 1-65535
    enum port_state state;
    struct {
        uint8_t ttl;
        enum result_reason type;
    } reason;
    struct nmap_error *error; // Error related to a single port
} __attribute__((__packed__));

struct scan_result {
    enum scan_type type;
    enum scan_state state;

    // Number of remaining port to be scanned.
    // An unemployed worker can directly choose the port `ports[remaining - 1]`,
    // and decrement remaining
    uint16_t remaining;

    // Allocated array, (randomized) ports, the main thread can only
    // access these element when the scan is done
    struct port_info *ports;
    // Error related to host (for ping or DNS scan for example)
    struct nmap_error *error;
} __attribute__((__packed__));

struct host {
    struct sockaddr_in addr;
    char *hostname_rsvl; // FQDN - resolved host with getnameinfo()
    char *hostname;
    enum host_state state;
    struct scan_result scans[SCAN_NBR];
};

struct dns_data {
    const char **hostname_rslv_ptr; // &host->hostname_rsvl
};

struct ping_data {
    int sock_eph;             // mock socket to lock an ephemeral port
    int sock_tcp;             // tcp raw socket
    int sock_icmp;            // icmp socket
    struct in_addr daddr;     // peer address
    struct sockaddr_in saddr; // tcp
    struct scan_result *rslt;
};

struct tcp_data {           // Used by SYN, ACK, NULL, XMAS, FIN
    uint8_t flag;           // TCP flag to send ()
    int sock_eph;           // mock socket to lock an ephemeral port
    int sock_tcp;           // tcp raw socket
    struct port_info *port; // result
};

struct connect_data {
    int sock_stream;      // bind to ephemeral port
    struct in_addr daddr; // peer address
    struct port_info *port;
};

struct udp_data {
    int sock_udp;         // binded to ephemeral port + connected to peer
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

struct task_handle {
    // Pointer toward rslt data. No race condition if assigned by host

    enum scan_type scan_type;

    union task_data data;
    struct timeval timeout;
    // Called at beginning of thread
    int (*init)(struct task_handle *data);
    // Called when send_state is toggled
    int (*packet_send)(struct task_handle *data);
    // Called when main_rcv or icmp_rcv is toggled
    int (*packet_rcv)(struct task_handle *data);
    // Called when timeout is toggled
    int (*packet_timeout)(struct task_handle *data);
    // Called when done or error is toggled
    int (*release)(struct task_handle *data);
    struct {
        uint8_t initialized : 1;
        uint8_t send_state : 1; // 0 => nothing sent, 1 => something sent
                                // (waiting for related response)
        uint8_t main_rcv : 1;   // incoming tcp/udp packet
        uint8_t icmp_rcv : 1;   // incoming icmp (for ping only)
        uint8_t timeout : 1;    // Timeout has been reached
        uint8_t done : 1;       // Scan complete
        uint8_t error : 1;      // Error
    } flags;
    struct nmap_error **error; // Ptr where errors must be registered
};

struct worker_handle { // 1 worker = 1 thread = 1 polling
    struct task_handle *tasks;
    unsigned int nbr_tasks;
};

struct nmap_error {
    int error;
    union { // Examples
        struct {

        } dns;
        struct {
            struct icmphdr icmphdr;
            uint8_t detail[8];
        } ping;
        struct {

        } scan;
    } u;
};

#endif