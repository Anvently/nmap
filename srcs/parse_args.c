#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <libft.h>
#include <netinet/in.h>
#include <nmap.h>
#include <string.h>

static int register_verbose(t_options *opt, char *);
static int register_help(t_options *opt, char *);
static int register_size(t_options *opt, char *);
static int register_numeric(t_options *opt, char *);
static int register_interface(t_options *opt, char *);
static int register_pattern(t_options *opt, char *);
static int register_ttl(t_options *opt, char *);
static int register_sequential(t_options *opt, char *);
static int register_usurp(t_options *opt, char *);
static int register_sim_ports(t_options *opt, char *);
static int register_list(t_options *opt, char *);
static int register_skip_discovery(t_options *opt, char *);
static int register_src_port(t_options *opt, char *);
static int register_open(t_options *opt, char *);
static int register_rtt_timeout_factor(t_options *opt, char *);
static int register_rtt_max(t_options *opt, char *);
static int register_ports(t_options *opt, char *);
static int register_threads(t_options *opt, char *);
static int register_scan(t_options *opt, char *);
static int register_file(t_options *opt, char *);
static int register_trace_packet(t_options *opt, char *);
static int register_no_service(t_options *opt, char *);

int NBR_OPTIONS = OPT_NBR;
t_opt_flag options_list[OPT_NBR] = {
    [OPT_VERBOSE] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_verbose,
                                 .short_id = 'v',
                                 .long_id = "verbose"},
    [OPT_HELP] = (t_opt_flag){.arg = ARG_NONE,
                              .handler = &register_help,
                              .short_id = '?',
                              .long_id = "help"},
    [OPT_SIZE] = (t_opt_flag){.arg = ARG_REQUIRED,
                              .handler = &register_size,
                              .short_id = 's',
                              .long_id = "size"},
    [OPT_NUMERIC] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_numeric,
                                 .short_id = 'n',
                                 .long_id = "numeric"},
    [OPT_INTERFACE] = (t_opt_flag){.arg = ARG_REQUIRED,
                                   .handler = &register_interface,
                                   .short_id = 'e',
                                   .long_id = "interface"},
    [OPT_PATTERN] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_pattern,
                                 .short_id = 0,
                                 .long_id = "data"},
    [OPT_TTL] = (t_opt_flag){.arg = ARG_REQUIRED,
                             .handler = &register_ttl,
                             .short_id = 0,
                             .long_id = "ttl"},
    [OPT_SEQUENTIAL] = (t_opt_flag){.arg = ARG_NONE,
                                    .handler = &register_sequential,
                                    .short_id = 'n',
                                    .long_id = "numeric"},
    [OPT_USURP] = (t_opt_flag){.arg = ARG_REQUIRED,
                               .handler = &register_usurp,
                               .short_id = 'S',
                               .long_id = "usurp"},
    [OPT_SIM_PORT] = (t_opt_flag){.arg = ARG_REQUIRED,
                                  .handler = &register_sim_ports,
                                  .short_id = 0,
                                  .long_id = "sim-ports"},
    [OPT_LIST] = (t_opt_flag){.arg = ARG_NONE,
                              .handler = &register_list,
                              .short_id = 'L',
                              .long_id = "list"},
    [OPT_SKIP_DISCOVERY] = (t_opt_flag){.arg = ARG_NONE,
                                        .handler = &register_skip_discovery,
                                        .short_id = 0,
                                        .long_id = "skip-ping"},
    [OPT_SRC_PORT] = (t_opt_flag){.arg = ARG_REQUIRED,
                                  .handler = &register_src_port,
                                  .short_id = 'g',
                                  .long_id = "source-port"},
    [OPT_OPEN] = (t_opt_flag){.arg = ARG_NONE,
                              .handler = &register_open,
                              .short_id = 0,
                              .long_id = "open"},
    [OPT_RTT_FACTOR] = (t_opt_flag){.arg = ARG_REQUIRED,
                                    .handler = &register_rtt_timeout_factor,
                                    .short_id = 0,
                                    .long_id = "rtt-factor"},
    [OPT_MAX_RTT] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_rtt_max,
                                 .short_id = 0,
                                 .long_id = "rtt-max"},
    [OPT_PORT] = (t_opt_flag){.arg = ARG_REQUIRED,
                              .handler = &register_ports,
                              .short_id = 'p',
                              .long_id = "port"},
    [OPT_THREADS] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_threads,
                                 .short_id = 't',
                                 .long_id = "threads"},
    [OPT_SCAN] = (t_opt_flag){.arg = ARG_REQUIRED,
                              .handler = &register_scan,
                              .short_id = 's',
                              .long_id = "scan"},
    [OPT_FILE] = (t_opt_flag){.arg = ARG_REQUIRED,
                              .handler = &register_file,
                              .short_id = 'f',
                              .long_id = "file"},
    [OPT_TRACE_PACKET] = (t_opt_flag){.arg = ARG_NONE,
                                      .handler = &register_trace_packet,
                                      .short_id = 0,
                                      .long_id = "trace-packet"},
    [OPT_NO_SERVICE] = (t_opt_flag){.arg = ARG_NONE,
                                    .handler = &register_no_service,
                                    .short_id = 'N',
                                    .long_id = "no-service"},
};

t_opt_flag *options_map = &options_list[0];

static int register_verbose(t_options *opt, char *arg) {
    (void)arg;
    opt->verbose += 1;
    return (0);
}
static int register_help(t_options *opt, char *arg) {
    (void)arg;
    opt->help = true;
    return (0);
}
static int register_size(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > 600)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("size", arg, NULL);
    else {
        opt->size = (unsigned int)rslt;
        return (0);
    }
    return (2);
}

static int register_numeric(t_options *opt, char *arg) {
    (void)arg;
    opt->numeric = true;
    return (0);
}

static int register_interface(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->interface = arg;
    return (0);
}
static int register_pattern(t_options *opt, char *arg) {
    opt->pattern = arg;
    while (*arg) {
        if (ft_strchr("0123456789abcdef", *arg) == NULL)
            return (ft_options_err_invalid_argument("pattern", arg, NULL));
        arg++;
    }
    return (0);
}

static int register_ttl(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > UINT8_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("ttl", arg, NULL);
    else {
        opt->ttl = (uint8_t)rslt;
        return (0);
    }
    return (2);
}

static int register_sequential(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->sequential = true;
    return (0);
}

static int register_usurp(t_options *opt, char *arg) {
    opt->usurp.arg = arg;
    if (inet_aton(arg, &opt->usurp.addr) == 0)
        return (ft_options_err_invalid_argument("usurp", arg, NULL));
    return (0);
}
static int register_sim_ports(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > UINT16_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("sim-ports", arg, NULL);
    else {
        opt->sim_ports = (uint16_t)rslt;
        return (0);
    }
    return (2);
}
static int register_list(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->list = true;
    return (0);
}
static int register_skip_discovery(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->skip_discovery = true;
    return (0);
}
static int register_src_port(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > UINT16_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("src_port", arg, NULL);
    else {
        opt->src_port = (uint16_t)rslt;
        return (0);
    }
    return (2);
}
static int register_open(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->open = true;
    return (0);
}
static int register_rtt_timeout_factor(t_options *opt, char *arg) {
    if (ft_strtof(arg, &opt->rtt_factor, NULL)) {
        ft_options_err_invalid_argument("rtt-timeout", arg, NULL);
        return (2);
    }
    if (opt->rtt_factor <= 0.f) {
        ft_options_err_invalid_argument("rtt-timeout", arg, NULL);
        return (2);
    }
    return (0);
}
static int register_rtt_max(t_options *opt, char *arg) {
    if (ft_strtof(arg, &opt->rtt_max, NULL)) {
        ft_options_err_invalid_argument("rtt-max", arg, NULL);
        return (2);
    }
    if (opt->rtt_max <= 0.f) {
        ft_options_err_invalid_argument("rtt-max", arg, NULL);
        return (2);
    }
    return (0);
}
static int register_ports(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->ports = arg;
    return (0);
}
static int register_threads(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > MAX_WORKER || rslt == 0)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("thread", arg, NULL);
    else {
        opt->threads = (uint16_t)rslt;
        return (0);
    }
    return (2);
}
static int strsidx(const char **strs, const char *str) {
    unsigned int idx = 0;

    while (strs[idx] != NULL) {
        if (strcmp(strs[idx], str) == 0)
            return (idx);
        idx++;
    }
    return (-1);
}

static int register_scan(t_options *opt, char *arg) {
    extern const char *scan_type_strings[11];
    const char **allowed_scan_types = scan_type_strings;
    char *delim = arg;
    int idx;

    opt->enabled_scan.int_representation = 0b11;
    while (*arg != '\0') {
        delim = strchrnul(arg, ',');
        if (*delim != '\0') {
            *delim = '\0';

            idx = strsidx(allowed_scan_types, arg);
            arg = delim + 1;
            if (idx < 0)
                return (ft_options_err_invalid_argument("scan", arg, NULL));
        } else {
            idx = strsidx(allowed_scan_types, arg);
            if (idx < 0)
                return (ft_options_err_invalid_argument("scan", arg, NULL));
            arg = delim;
        }
        opt->enabled_scan.int_representation |= (uint16_t)(1 << (idx));
    }
    return (0);
}
static int register_file(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->file = arg;
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
uint16_t *parse_ports(const char *ports) {
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

int check_options(t_options *options) {
    if (options->help)
        return (0);
    if (options->list) {
        options->enabled_scan.int_representation = 0;
        options->enabled_scan.dns = 1;
    }
    options->enabled_scan.ping = options->skip_discovery ? 0 : 1;
    options->port_vec = parse_ports(options->ports);
    if (options->enabled_scan.connect) {
        if (options->enabled_scan.int_representation ==
            ((1 << SCAN_CONNECT) | (1 << SCAN_DNS) | (1 << SCAN_PING)))
            printf("Note: if you are trying to attempt an unprivileged scan, "
                   "use --skip-ping in addition to connect scan\n");
        if (options->ttl == 0)
            printf("Warning: ttl will be set to 1 for CONN scan\n");
        if (options->usurp.arg)
            ft_options_err_incompatible_options("CONNECT scan", "usurp");
        if (options->src_port)
            ft_options_err_incompatible_options("CONNECT scan", "source-port");
    }
    return (0);
}

static int register_trace_packet(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->trace_packet = true;
    return (0);
}

static int register_no_service(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    opt->no_service = true;
    return (0);
}