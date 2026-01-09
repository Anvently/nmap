#include <libft.h>
#include <stdint.h>
#include <sys/time.h>

#ifndef FT_PING_H
#define FT_PING

#define MIN_FLOOD_TIME 10.f

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

    OPT_NBR, //
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

typedef struct s_ping_rslt {
    uint16_t seq; // Caller
    struct timeval send_stamp;
    struct timeval rcv_stamp;
    float rtt;
    int error;
    unsigned int error_code;
    const char *buffer;
    unsigned int buffer_out_len;
    unsigned int buffer_in_len;
} t_ping_result;

typedef struct s_ping_score {
    unsigned int total;
    unsigned int success;
    float mean;
    float M2;
    float min;
    float max;
} t_ping_score;

#define ICMP_HDR_SIZE 28

int ping(const char *hostname, t_options *opts);
#endif