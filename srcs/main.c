#include <libft.h>
#include <netinet/ip.h>
#include <nmap.h>

const char *executable_name = "ft_ping";

static const char help[] = "\n\
Usage: ft_ping [OPTION...] HOST ...\n\
Send ICMP ECHO_REQUEST packets to network hosts.\n\
\n\
  -e, --interface               use specified interface\n\
  -n, --numeric                 never do DNS resolution\n\
  -R, --resolve                 always do DNS resolution\n\
      --ttl=N                   specify N as time-to-live\n\
  -g, --source-port=N           specify source port\n\
  -v, --verbose                 verbose output\n\
      --data=PATTERN            fill ICMP packet with given pattern (hex)\n\
  -r, --sequential              do not randomize port and scan them in order (user-order)\n\
  -f, --mtu=NUMBER              fragment packets with given MTU\n\
  -S, --usurp=ADDRESS           spoof source address\n\
      --reason                  display how a port state was resolved\n\
      --open                    only display open or possibly opened ports\n\
      --all                     display every port, even those marked as filtered or closed\n\
      --skip-ping               skip host discorvery and treat all hosts as online\n\
  -L, --list                    only list host that responded to ping but do not scan ports\n\
  -p, --port=[PORT,MIN-MAX,...] specify custom port to scan, takes individual port or ranges (default to 1-1024)\n\
  -t, --threads                 specify a maximum number of threads to use (1-250), default to 16\n\
  -s, --scan=[list...]          specify which scan to use (default to all)\n\
      --file                    read hostname from a file\n\
  -?, --help                    give this help list\n";

static const char no_argument[] = "ft_ping: missing host operand\n\
Try 'ft_ping -?' for more information.";

int main(int argc, char **argv) {
    t_options options = {.size = 56,
                         .pattern = NULL,
                         .ttl = 255,
                         .tos = IPTOS_CLASS_DEFAULT,
                         .linger_timeout = 1,
                         .interval = -1.f};
    unsigned int nbr_args = 0;
    printf("port_info=%lu\n"
           "scan_result=%lu\n",
           sizeof(struct port_info), sizeof(struct scan_result));
    if (ft_options_retrieve(argc - 1, argv + 1, &options, &nbr_args))
        return (2);
    if (options.help) {
        ft_dprintf(1, "%s\n", help);
        return (0);
    }
    if (nbr_args == 0) {
        ft_dprintf(1, "%s\n", no_argument);
        return (1);
    }

    return (0);
}