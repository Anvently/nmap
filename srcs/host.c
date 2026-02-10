
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <memory.h>
#include <nmap.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void print_host(struct host *host);

struct host *check_double_host(struct host *vec_hosts, struct host *host);

/// @brief Should not have to be called in case of errors.
/// @param hosts
void hosts_free(struct host **hosts) {
    size_t nbr_host;
    struct host *host;

    if (*hosts == NULL)
        return;
    host = *hosts;
    nbr_host = ft_vector_size(*hosts);
    while (nbr_host--) {
        if (host->hostname_rsvl)
            free(host->hostname_rsvl);
        for (unsigned int i = SCAN_DNS; i < SCAN_NBR; i++) {
            if (host->scans[i].state != SCAN_DISABLE) {
                for (unsigned j = 0; j < host->scans[i].nbr_port; j++) {
                    if (host->scans[i].ports[j].error)
                        free(host->scans[i].ports[j].error);
                }
                if (host->scans[i].ports)
                    free(host->scans[i].ports);
            }
            if (host->scans[i].error)
                free(host->scans[i].error);
        }
        host++;
    }
    ft_vector_free((t_vector **)hosts);
}

/// @brief Allocate and randomize array of port_info base on
/// vector of ports.
/// @return ```NULL``` if allocation fails
static struct port_info *allocate_ports(uint16_t *vec_ports,
                                        bool dont_randomize) {
    const uint16_t nbr_port = (uint16_t)ft_vector_size(vec_ports);
    struct port_info *ports = calloc(nbr_port, sizeof(struct port_info));

    for (uint16_t i = 0; i < nbr_port; i++) {
        ports[i].port = vec_ports[i];
    }
    if (dont_randomize || nbr_port < 2)
        return (ports);
    for (uint16_t i = nbr_port - 1; i > 0; i--) {
        uint32_t j = (uint32_t)(rand() % (i + 1));
        ft_memswap(ports + i, ports + j, sizeof(struct port_info));
    }
    return (ports);
}

/// @brief Check if ```host``` is matching another host in ```vec_hosts```.
/// Check for hostname match AND ipv4 match. Handle the case where ```host```
/// itself is already contained within ```hosts_vec```
/// @param hosts
/// @param host
/// @return ```duplicated host``` if host has a doubloon.
struct host *check_double_host(struct host *vec_hosts, struct host *host) {
    const unsigned int nbr_host = ft_vector_size(vec_hosts);
    for (unsigned int i = 0; i < nbr_host; i++) {
        if (&vec_hosts[i] == host || vec_hosts[i].state == STATE_DOUBLOON)
            continue; // case where host is already stored in vector or multiple
                      // doubloons
        if (strcmp(host->hostname, vec_hosts[i].hostname) == 0)
            return (&vec_hosts[i]);
        // Only compare ipv4 address after dns resolution (0.0.0.0 at first)
        if (vec_hosts[i].state >= STATE_RESOLVED &&
            memcmp(&host->addr, &vec_hosts[i].addr, sizeof(host->addr)) == 0)
            return (&vec_hosts[i]);
    }
    return (NULL);
}

struct static_vec {
    t_vector_header hdr;
    uint16_t ports[5];
};

/// @brief Generate a pre-filled host structure (with ports structure allocated)
/// and push it to vector
/// @param hosts
/// @param hostname
/// @param vec_ports
/// @param opts
/// @return ```0``` for success, currently exit on every possible error.
static int add_host(struct host **hosts, const char *hostname,
                    uint16_t *vec_ports, t_options *opts) {
    struct host host = {.hostname = hostname};
    struct host *doubloon_match;
    unsigned int nbr_port = ft_vector_size(vec_ports);
    struct static_vec ping_ports = {
        .hdr = {.capacity = 5, .len = 5, .type_size = sizeof(uint16_t)},
        .ports = {80, 443, 21, 22, 25}};

    // Need to check for doubloons
    doubloon_match = check_double_host(*hosts, &host);
    if (doubloon_match) {
        host.state = STATE_DOUBLOON;
        if (ft_vector_push((t_vector **)hosts, &host))
            error(-1, errno, "pushing a new host in vector");
        return (0);
    }

    host.state = STATE_PENDING_RESOLVE;
    // DNS scan - always
    host.scans[SCAN_DNS] = (struct scan_result){
        .remaining = 0, .type = SCAN_DNS, .state = SCAN_PENDING, .ports = NULL};

    // Port scans
    if (opts->list == false) {
        for (unsigned int i = SCAN_PING; i < SCAN_NBR; i++) {

            host.scans[i] = (struct scan_result){.remaining = 0,
                                                 .nbr_port = 0,
                                                 .state = SCAN_DISABLE,
                                                 .type = i};

            // If scan is enabled
            if (((uint16_t)opts->enabled_scan.int_representation &
                 ((uint16_t)1 << i)) != 0) {

                host.scans[i].state = SCAN_PENDING;
                if (host.scans[i].type == SCAN_PING) {
                    host.scans[i].nbr_port = 5;
                    host.scans[i].ports =
                        allocate_ports(ping_ports.ports, true);
                } else {
                    host.scans[i].nbr_port = nbr_port;
                    host.scans[i].ports =
                        allocate_ports(vec_ports, opts->sequential);
                }
                if (host.scans[i].ports == NULL)
                    error(-1, errno,
                          "allocating port_info structure for scan %hhu", i);
            }
            host.scans[i].remaining = host.scans[i].nbr_port;
        }
    }

    // Adding to vector
    if (ft_vector_push((t_vector **)hosts, &host))
        error(-1, errno, "pushing a new host in vector");
    return (0);
}

/// Cmp function to sort port vector
static int cmp(void *a, void *b) {
    if (*(uint16_t *)a < *(uint16_t *)b)
        return (-1);
    else
        return (1);
}

/// @brief
/// @param ports
/// @param n
/// @return ```Duplicated port (1-65535)``` or ```0``` if none.
static uint16_t find_duplicate_ports(uint16_t *ports, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        if (i + 1 < n && ports[i] == ports[i + 1])
            return (ports[i]);
    }
    return (0);
}

/// @brief Push a port into vector, while checking for ```MAX_PORT_NBR```
/// @param vec_ports
/// @param port
/// @return ```0``` for success, ```1``` if limits reached
static int push_port(uint16_t *vec_ports, uint16_t port) {
    if (ft_vector_size(vec_ports) >= MAX_PORT_NBR)
        return (1);
    ft_vector_push((t_vector **)&vec_ports, &port);
    return (0);
}

/// @brief Parse ports string, fill a corresponding port vector (1 port = 1
/// element) and check for duplicate
/// @param ports
/// @return Allocated port vector, exit on error (never returns ```NULL```)
static uint16_t *parse_ports(const char *ports) {
    uint16_t *vec_ports = ft_vector_create(sizeof(uint16_t), MAX_PORT_NBR),
             duplicate;
    unsigned long min, max;
    const char *ptr = ports, *element;

    if (vec_ports == NULL)
        error(-1, errno, "allocating ports vector");

    while (*ptr) {
        element = ptr;
        if (ft_strtoul_base(ptr, &min, &ptr, "0123456789") ||
            min > UINT16_MAX || min == 0)
            error(1, errno, "Invalid port range `%s' near `%.4s...'", ports,
                  element);
        if (*ptr == ',' || *ptr == '\0') {
            if (push_port(vec_ports, (uint16_t)min))
                error(1, errno,
                      "Invalid port range `%s' : exceed number of ports "
                      "allowed (%u)",
                      ports, MAX_PORT_NBR);
            if (*ptr == ',')
                ptr++;
        } else if (*ptr == '-') {
            ++ptr;
            if (*ptr == '\0' ||
                ft_strtoul_base(ptr, &max, &ptr, "0123456789") ||
                max > UINT16_MAX || max == 0)
                error(1, errno, "Invalid port range `%s' near `%.4s...'", ports,
                      element);
            for (unsigned int i = min; i <= max; i++) {
                if (push_port(vec_ports, (uint16_t)i))
                    error(1, errno,
                          "Invalid port range `%s' : exceed number of ports "
                          "allowed (%u)",
                          ports, MAX_PORT_NBR);
            }
            if (*ptr == ',')
                ptr++;
        } else {
            error(1, errno, "Invalid port range `%s' near `%.4s...'", ports,
                  element);
        }
    }
    max = ft_vector_size(vec_ports);
    if (max == 0)
        error(1, 0, "no ports");
    if (ft_vector_resize((t_vector **)&vec_ports, max))
        error(-1, errno, "shrinking ports vector");
    if (ft_merge_sort(vec_ports, max, cmp, false))
        error(-1, errno, "sorting port vector");
    duplicate = find_duplicate_ports(vec_ports, max);
    if (duplicate)
        error(1, 0, "duplicate port %hu", duplicate);
    return (vec_ports);
}

static void add_hosts_from_file(struct host **vec_hosts, uint16_t *vec_ports,
                                t_options *opts) {
    struct stat file_stats;
    char *mapped;
    size_t i = 0, start;
    size_t size;
    int fd;
    fd = open(opts->file, O_RDONLY, 0);
    if (fd < 0)
        error(1, errno, "opening input file %s", opts->file);
    if (fstat(fd, &file_stats) < 0)
        error(1, errno, "fstat() on file %s", opts->file);
    size = file_stats.st_size;
    if (size == 0) {
        close(fd);
        return;
    }
    mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED)
        error(1, errno, "mapping file %s", opts->file);
    while (i < size && mapped[i]) {
        while (i < size && ft_isspace(mapped[i]))
            i++;
        start = i;
        while (i < size && ft_isspace(mapped[i]) == false)
            i++;
        if (i - start > 0) {
            mapped[i++] = '\0';
            add_host(vec_hosts, mapped + start, vec_ports, opts);
        }
    }
    if (errno != 0)
        error(1, errno, "reading input file %s", opts->file);
    close(fd);
}

/// Parse host and ports argument and allocate pre-filled host structure
/// Exit on errrors.
struct host *hosts_create(char **args, unsigned int nbr_args, t_options *opts) {
    int ret = 0;
    uint16_t *vec_ports = parse_ports(opts->ports);
    struct host *vec_hosts = ft_vector_create(sizeof(struct host), 1);

    if (vec_hosts == NULL)
        error(-1, errno, "allocating host vector");
    while (nbr_args) {
        if (*args != NULL) {
            if ((ret = add_host(&vec_hosts, *args, vec_ports, opts)))
                break;
            nbr_args--;
        }
        args++;
    }
    if (opts->file)
        add_hosts_from_file(&vec_hosts, vec_ports, opts);
    // ft_vector_iter((t_vector **)vec_hosts, (void (*)(void *))print_host);
    ft_vector_free((t_vector **)&vec_ports);
    return (vec_hosts);
}