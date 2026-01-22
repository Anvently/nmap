#include <libft.h>
#include <netinet/ip.h>
#include <nmap.h>

const char *executable_name = "ft_ping";

static const char help[] = "\n\
Usage: ft_ping [OPTION...] HOST ...\n\
Send ICMP ECHO_REQUEST packets to network hosts.\n\
\n\
 Options valid for all request types:\n\
  -i, --interval=NUMBER      wait NUMBER seconds between sending each packet\n\
      --id=NUMBER            choose a custom identifier for ICMP packet\n\
  -n, --numeric              do not resolve host addresses\n\
  -r, --ignore-routing       send directly to a host on an attached network\n\
      --ttl=N                specify N as time-to-live\n\
  -T, --tos=NUM              set type of service (TOS) to NUM\n\
  -v, --verbose              verbose output\n\
  -w, --timeout=N            stop after N seconds\n\
  -W, --linger=N             number of seconds to wait for response\n\
\n\
 Options valid for --echo requests:\n\
\n\
  -f, --flood                flood ping (root only)\n\
  -l, --preload=NUMBER       send NUMBER packets as fast as possible before\n\
                             falling into normal mode of behavior (root only)\n\
  -p, --pattern=PATTERN      fill ICMP packet with given pattern (hex)\n\
  -s, --size=NUMBER          send NUMBER data octets\n\
\n\
  -?, --help                 give this help list\n";

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