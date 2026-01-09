#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <ft_nmap.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

int register_socket(t_options *opts);
int fill_addr_info(const char *hostname, struct addrinfo **dst,
                   t_options *opts);
float compute_rtt(struct timeval start, struct timeval end);
char *get_ip_name(struct sockaddr *addr, bool resolve);

bool stop = false;

void print_verbose_packet(const char *buffer, unsigned int size);

int ping(const char *hostname, t_options *opts) {
    struct addrinfo *addr = NULL;
    t_ping_score score = {.min = UINT32_MAX};
    int fd = -1;

    if ((fd = register_socket(opts)) < 0)
        return (1);
    if (fill_addr_info(hostname, &addr, opts) || addr->ai_addr == NULL)
        return (1);
    printf("PING %s (%s) : %u data bytes", addr->ai_canonname,
           get_ip_name(addr->ai_addr, false), opts->size);
    if (opts->verbose)
        printf(", id %1$#06x = %1$u", opts->identifier);
    printf("\n");
    ping_loop(addr, opts, fd, &score);
    print_score(hostname, &score);
    freeaddrinfo(addr);
    return (0);
}