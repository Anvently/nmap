#include <nmap.h>

static int register_verbose(t_options *opt, char *);
static int register_help(t_options *opt, char *);
static int register_size(t_options *opt, char *);
static int register_pattern(t_options *opt, char *);
static int register_numeric(t_options *opt, char *);
static int register_ttl(t_options *opt, char *);

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
    [OPT_PATTERN] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_pattern,
                                 .short_id = 'p',
                                 .long_id = "pattern"},
    [OPT_NUMERIC] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_numeric,
                                 .short_id = 'n',
                                 .long_id = "numeric"},
    [OPT_TTL] = (t_opt_flag){.arg = ARG_REQUIRED,
                             .handler = &register_ttl,
                             .short_id = 0,
                             .long_id = "ttl"},
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
