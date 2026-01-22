#include <nmap.h>

static int register_verbose(t_options *opt, char *);
static int register_help(t_options *opt, char *);
static int register_size(t_options *opt, char *);
static int register_numeric(t_options *opt, char *);
static int register_resolve(t_options *opt, char *);
static int register_interface(t_options *opt, char *);
static int register_pattern(t_options *opt, char *);
static int register_ttl(t_options *opt, char *);
static int register_sequential(t_options *opt, char *);
static int register_fragment(t_options *opt, char *);
static int register_usurp(t_options *opt, char *);
static int register_reason(t_options *opt, char *);
static int register_list(t_options *opt, char *);
static int register_skip_discovery(t_options *opt, char *);
static int register_src_port(t_options *opt, char *);
static int register_open(t_options *opt, char *);
static int register_all(t_options *opt, char *);
static int register_ports(t_options *opt, char *);
static int register_threads(t_options *opt, char *);
static int register_scan(t_options *opt, char *);
static int register_file(t_options *opt, char *);

int NBR_OPTIONS = OPT_NBR;
t_opt_flag options_list[OPT_NBR] = {
    [OPT_VERBOSE] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_verbose,
                                 .short_id = 'v',
                                 .long_id = "verbose"},
    [OPT_HELP] = (t_opt_flag){.arg = ARG_NONE,
                              .handler = &register_help,
                              .short_id = 'h',
                              .long_id = "help"},
    [OPT_SIZE] = (t_opt_flag){.arg = ARG_REQUIRED,
                              .handler = &register_size,
                              .short_id = 's',
                              .long_id = "size"},
    [OPT_NUMERIC] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_numeric,
                                 .short_id = 'n',
                                 .long_id = "numeric"},
    [OPT_RESOLVE] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_resolve,
                                 .short_id = 'R',
                                 .long_id = "resolve"},
    [OPT_INTERFACE] = (t_opt_flag){.arg = ARG_REQUIRED,
                                   .handler = &register_interface,
                                   .short_id = 'e',
                                   .long_id = "interface"},
    [OPT_PATTERN] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_pattern,
                                 .short_id = 'p',
                                 .long_id = "pattern"},
    [OPT_TTL] = (t_opt_flag){.arg = ARG_REQUIRED,
                             .handler = &register_ttl,
                             .short_id = 0,
                             .long_id = "ttl"},
    [OPT_SEQUENTIAL] = (t_opt_flag){.arg = ARG_NONE,
                                    .handler = &register_sequential,
                                    .short_id = 'n',
                                    .long_id = "numeric"},
    [OPT_FRAGMENT] = (t_opt_flag){.arg = ARG_OPTIONNAL,
                                  .handler = &register_fragment,
                                  .short_id = 'f',
                                  .long_id = "mtu"},
    [OPT_USURP] = (t_opt_flag){.arg = ARG_REQUIRED,
                               .handler = &register_usurp,
                               .short_id = 'S',
                               .long_id = "usurp"},
    [OPT_REASON] = (t_opt_flag){.arg = ARG_NONE,
                                .handler = &register_reason,
                                .short_id = 0,
                                .long_id = "reason"},
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
    [OPT_ALL] = (t_opt_flag){.arg = ARG_NONE,
                             .handler = &register_all,
                             .short_id = 0,
                             .long_id = "all"},
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
};

t_opt_flag *options_map = &options_list[0];

static int register_verbose(t_options *opt, char *arg) {
    (void)arg;
    opt->verbose = true;
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
    if (rslt > INT_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("size", arg, NULL);
    else {
        opt->size = (unsigned int)rslt;
        return (0);
    }
    return (2);
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
static int register_numeric(t_options *opt, char *arg) {
    (void)arg;
    opt->numeric = true;
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
int check_options(t_options *options) {
    (void)options;
    return (0);
}

static int register_resolve(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_interface(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_pattern(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_ttl(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_sequential(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_fragment(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_usurp(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_reason(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_list(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_skip_discovery(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_src_port(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_open(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_all(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_ports(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_threads(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_scan(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}
static int register_file(t_options *opt, char *arg) {
    (void)arg;
    (void)opt;
    return (0);
}