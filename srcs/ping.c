#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <nmap.h>
#include <signal.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include <nmap.h>

int ping_init(struct task_handle *data);
int ping_packet_send(struct task_handle *data);
int ping_packet_rcv(struct task_handle *data);
int ping_packet_timeout(struct task_handle *data);
int ping_release(struct task_handle *data);

int ping_init(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_packet_send(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_packet_rcv(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_packet_timeout(struct task_handle *data) {
    (void)data;
    return (0);
}

int ping_release(struct task_handle *data) {
    (void)data;
    return (0);
}