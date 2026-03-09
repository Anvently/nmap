#include <libft.h>
#include <netinet/ip.h>
#include <nmap.h>
#include <stdio.h>
#include <time.h>

const char *executable_name = "ft_nmap";
const char *invoc_name;

static const char help[] = "\n\
Usage: ft_nmap [OPTION...] HOST ...\n\
Scan host port and more.\n\
\n\
  -e, --interface               use specified interface\n\
  -n, --numeric                 never do DNS resolution\n\
      --ttl=N                   specify N as time-to-live. Default to %hhu.\n\
  -g, --source-port=N           specify source port\n\
  -v, --verbose                 verbose output\n\
      --data=PATTERN            fill payloads with given pattern (hex)\n\
  -r, --sequential              do not randomize port and scan them in order (user-order)\n\
  -f, --mtu=NUMBER              fragment packets with given MTU\n\
  -S, --usurp=ADDRESS           spoof source address\n\
      --sim-ports               max number of ports being scan simultaneously for a single host. Default to %hu\n\
      --open                    only display open or possibly opened ports\n\
      --rtt-factor=factor       set factor used to calculate port timeout based on last host rtt (timeout=rtt*factor). Default to %.2f.\n\
      --rtt-max=max             Maximum allowed timeout for a probe. Default to %.2f.\n\
      --skip-ping               skip host discovery and treat all hosts as online\n\
  -L, --list                    only list host that responded to ping but do not scan ports\n\
  -N, --no-service              do not resolve service name\n\
      --trace-packet            print every packet sended and received\n\
  -p, --port=[PORT,MIN-MAX,...] specify custom port to scan, takes individual port or ranges. Default to %s.\n\
  -t, --threads                 specify a maximum number of threads to use (1-250), default to %hu.\n\
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
                                .pattern = "0123456789abcdef",
                                .rtt_factor = DFT_PORT_TIMEOUT_FACTOR,
                                .rtt_max = DFT_MAX_RTT,
                                .sim_ports = MAX_SIM_PORT};

int main(int argc, char **argv) {
    t_options options = dft_options;
    unsigned int nbr_args = 0;
    srand(time(NULL));
    invoc_name = argv[0];
    if (ft_options_retrieve(argc - 1, argv + 1, &options, &nbr_args))
        return (2);
    if (options.help) {
        printf(help, dft_options.ttl, dft_options.sim_ports,
               dft_options.rtt_factor, dft_options.rtt_max, dft_options.ports,
               dft_options.threads);
        return (0);
    }
    if (nbr_args == 0 && options.file == NULL) {
        printf("%s\n", no_argument);
        return (1);
    }
    return (ft_nmap(argv + 1, nbr_args, &options));
}