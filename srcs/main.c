#include <libft.h>
#include <netinet/ip.h>
#include <nmap.h>
#include <time.h>

const char *executable_name = "ft_nmap";

static const char help[] = "\n\
Usage: ft_nmap [OPTION...] HOST ...\n\
Scan host port and more.\n\
\n\
  -e, --interface               use specified interface\n\
  -n, --numeric                 never do DNS resolution\n\
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
      --trace-packet            print every packet sended and received\n\
  -p, --port=[PORT,MIN-MAX,...] specify custom port to scan, takes individual port or ranges (default to 1-1024)\n\
  -t, --threads                 specify a maximum number of threads to use (1-250), default to 16\n\
  -s, --scan=[list...]          specify which scan to use (default to all)\n\
      --file                    read hostname from a file\n\
  -?, --help                    give this help list\n";

static const char no_argument[] = "ft_nmap: missing host operand\n\
Try 'ft_nmap -?' for more information.";

static t_options dft_options = {.size = 0,
                                .enabled_scan.int_representation =
                                    0xFFFF >> (16 - SCAN_NBR),
                                .ports = "1-1024",
                                .threads = 16,
                                .ttl = 64,
                                .pattern = "0123456789abcdef"};

int main(int argc, char **argv) {
    t_options options = dft_options;
    unsigned int nbr_args = 0;
    srand(time(NULL));
    if (ft_options_retrieve(argc - 1, argv + 1, &options, &nbr_args))
        return (2);
    if (options.help) {
        ft_dprintf(1, "%s\n", help);
        return (0);
    }
    if (nbr_args == 0 && options.file == NULL) {
        ft_dprintf(1, "%s\n", no_argument);
        return (1);
    }
    return (ft_nmap(argv + 1, nbr_args, &options));
}