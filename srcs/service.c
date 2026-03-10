#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libgen.h>
#include <nmap.h>
#include <sys/stat.h>

extern const char *invoc_name;

const char *retrieve_service_name(enum scan_type type, uint16_t port,
                                  struct service *vec_services) {
    const unsigned int nbr_services = ft_vector_size(vec_services);
    const char *name = "unknown";

    for (unsigned int i = 0; i < nbr_services; i++) {
        if (vec_services[i].port == port) {
            if ((vec_services[i].type == SERVICE_TCP && type != SCAN_UDP) ||
                (vec_services[i].type == SERVICE_UDP && type == SCAN_UDP)) {
                if (vec_services[i].name)
                    name = vec_services[i].name;
                break;
            }
        }
        if (vec_services[i].port > port)
            break;
    }
    return (name);
}

/// @brief In order to find port-service mapping file, different strategies are
/// tried:
///
/// 1 : Check for env variable NMAP_SERVICES_FILE (default to /usr/share/nmap)
/// 2 : Check for file name nnmap-services in working directory
/// 3 : If no match, return NULL
/// @return statically allocated string
static const char *check_nmap_source() {
    struct stat rslt;
    static char static_path[128];
    const char *path = getenv("NMAP_SERVICES_FILE");
    char *directory;

    if (path == NULL)
        path = "/usr/share/nmap/nmap-services";

    if (stat(path, &rslt)) {
        fprintf(stdout, "Unable to retrieve service names from environment "
                        "variable NMAP_SERVICES_FILE (defaulting to "
                        "/usr/share/nmap/nmap-services). If any, a file named "
                        "nmap-services in working directory will be used.\n");
        directory = strdup(invoc_name);
        path = dirname(directory);
        ft_strlcpy(static_path, path, sizeof(static_path));
        ft_strlcat(static_path, "/nmap-services", sizeof(static_path));
        free(directory);
        if (stat(static_path, &rslt)) {
            fprintf(stdout,
                    "%s: not found, service resolution will be disabled.\n",
                    static_path);
            return (NULL);
        }
        return (static_path);
    } else {
        ft_strlcpy(static_path, path, sizeof(static_path));
        return (static_path);
    }
}

/// Cmp function to sort service vector
static int cmp(void *a, void *b) {
    if (((struct service *)a)->port <= ((struct service *)b)->port)
        return (-1);
    else
        return (1);
}

void free_services_vec(struct service *vec_services) {
    if (vec_services == NULL)
        return;
    const unsigned int nbr_service = ft_vector_size(vec_services);
    for (unsigned int i = 0; i < nbr_service; i++) {
        if (vec_services[i].name)
            free(vec_services[i].name);
    }
    ft_vector_free((t_vector **)&vec_services);
}

static char *skip_space(char **ptr) {
    while (ft_isspace(**ptr))
        *ptr = *ptr + 1;
    return (*ptr);
}

static int read_services_name(unsigned int nbr_service,
                              struct service services[nbr_service],
                              const char *path) {
    unsigned int idx = 0, name_len;
    char *line = NULL, *name, *ptr;
    unsigned long port;
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return (-1);
    errno = 0;
    while (idx < nbr_service) {
        line = ptr = ft_gnl(fd);
        if (line == NULL) {
            break;
        }
        if (*skip_space(&ptr) == '#') {
            free(line);
            continue;
        }
        name = ptr;
        while (ft_isspace(*ptr) == false && *ptr)
            ptr++;
        name_len = ptr - name;
        if (ft_strtoul_base(ptr, &port, (const char **)&ptr, "0123456789") ||
            port < services[idx].port) {
            free(line);
            continue;
        }
        while (idx < nbr_service && port > services[idx].port) {
            idx++;
        }
        if (idx >= nbr_service || port != services[idx].port) {
            free(line);
            continue;
        }
        if (*ptr++ != '/') {
            free(line);
            continue;
        }
        if ((strncmp(ptr, "tcp", 3) == 0 &&
             services[idx].type == SERVICE_TCP) ||
            (strncmp(ptr, "udp", 3) == 0 &&
             services[idx].type == SERVICE_UDP)) {
            services[idx++].name = strndup(name, name_len);
        }
        free(line);
    }
    close(fd);
    if (errno != 0)
        return (-1);
    return (0);
}

static void print_service_name() __attribute_maybe_unused__;

static void print_service_name(struct service *services_vec) {
    static const char *string_service_type[] = {[SERVICE_NONE] = "none",
                                                [SERVICE_TCP] = "tcp",
                                                [SERVICE_UDP] = "udp",
                                                [SERVICE_BOTH] = "both"};
    const size_t size = ft_vector_size(services_vec);

    for (size_t i = 0; i < size; i++) {
        printf("%hu/%s: %s\n", services_vec[i].port,
               string_service_type[services_vec[i].type], services_vec[i].name);
    }
}

/// @brief Allocate a vector of service struct containing every service name
/// required
struct service *retrieve_services(uint16_t *vec_ports,
                                  union scan_list enabled_scan) {
    const char *path = check_nmap_source();
    const uint16_t nbr_ports = ft_vector_size(vec_ports);
    struct service *vec_services;
    struct service service;
    enum service_type service_needed = SERVICE_NONE;
    unsigned int nbr_service;

    if (path == NULL)
        return (NULL);

    if (enabled_scan.udp)
        service_needed = SERVICE_BOTH; // TCP names used for conclusion
    else if ((enabled_scan.int_representation & SCAN_LIST_TCP_MASK))
        service_needed = SERVICE_TCP;
    nbr_service = nbr_ports * (service_needed == SERVICE_BOTH   ? 2
                               : service_needed == SERVICE_NONE ? 0
                                                                : 1);
    vec_services = ft_vector_create(sizeof(struct service), nbr_service);
    if (vec_services == NULL)
        error(-1, errno, "allocating services mapping vector");
    for (unsigned int i = 0, j = 0; i < nbr_ports; i++) {
        if (service_needed == SERVICE_BOTH || service_needed == SERVICE_TCP) {
            service =
                (struct service){.port = vec_ports[i], .type = SERVICE_TCP};
            ft_vector_push((t_vector **)&vec_services, &service);
            j++;
        }
        if (service_needed == SERVICE_BOTH || service_needed == SERVICE_UDP) {
            service =
                (struct service){.port = vec_ports[i], .type = SERVICE_UDP};
            ft_vector_push((t_vector **)&vec_services, &service);
            j++;
        }
    }
    if (ft_merge_sort(vec_services, nbr_service, cmp, false))
        error(-1, errno, "sorting service mapping vector");
    if (read_services_name(nbr_service, vec_services, path)) {
        error(0, errno,
              "reading services name mapping file\nService resolution will be "
              "disabled.");
        free_services_vec(vec_services);
        return (NULL);
    }
    return (vec_services);
}