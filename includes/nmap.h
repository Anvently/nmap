#include <libft.h>
#include <netinet/ip_icmp.h>
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
#define MAX_WORKER_ASYNC 100
#define MAX_WORKER_THREADS 250

enum host_state {
    STATE_ERROR = -2, // Error received
    STATE_DOWN = -1,  // Ping failed (host unreachable)

    STATE_PENDING_RESOLVE = 0, // Was inputed by user

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
    SCAN_SYN = 0,
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
} __attribute__((__packed__));

struct host {
    struct sockaddr_in addr;
    char *hostname_rsvl; // FQDN - resolved host with getnameinfo()
    char *hostname;
    enum host_state state;
    struct scan_result scans[SCAN_NBR];
    struct nmap_error error;
};

struct worker_data {
    enum scan_type scan_type;
    struct port_info *rslt; // Pointer toward rslt data. !!! Race-condition !!!
};

struct nmap_error {
    int errno;
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