#include <ft_nmap.h>

static int register_verbose(t_options *opt, char *);
static int register_help(t_options *opt, char *);
static int register_size(t_options *opt, char *);
static int register_pattern(t_options *opt, char *);
static int register_timeout(t_options *opt, char *);
static int register_linger(t_options *opt, char *);
static int register_identifier(t_options *opt, char *);
static int register_numeric(t_options *opt, char *);
static int register_tos(t_options *opt, char *);
static int register_ttl(t_options *opt, char *);
static int register_ignore_routing(t_options *opt, char *);
static int register_interval(t_options *opt, char *);
static int register_flood(t_options *opt, char *);
static int register_preload(t_options *opt, char *);

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
    [OPT_TIMEOUT] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_timeout,
                                 .short_id = 'w',
                                 .long_id = "timeout"},
    [OPT_LINGER] = (t_opt_flag){.arg = ARG_REQUIRED,
                                .handler = &register_linger,
                                .short_id = 'W',
                                .long_id = "linger"},
    [OPT_IDENTIFIER] = (t_opt_flag){.arg = ARG_REQUIRED,
                                    .handler = &register_identifier,
                                    .short_id = 0,
                                    .long_id = "id"},
    [OPT_NUMERIC] = (t_opt_flag){.arg = ARG_NONE,
                                 .handler = &register_numeric,
                                 .short_id = 'n',
                                 .long_id = "numeric"},
    [OPT_TOS] = (t_opt_flag){.arg = ARG_REQUIRED,
                             .handler = &register_tos,
                             .short_id = 'T',
                             .long_id = "tos"},
    [OPT_TTL] = (t_opt_flag){.arg = ARG_REQUIRED,
                             .handler = &register_ttl,
                             .short_id = 0,
                             .long_id = "ttl"},
    [OPT_DONT_ROUTE] = (t_opt_flag){.arg = ARG_NONE,
                                    .handler = &register_ignore_routing,
                                    .short_id = 'r',
                                    .long_id = "ignore-routing"},
    [OPT_INTERVAL] = (t_opt_flag){.arg = ARG_REQUIRED,
                                  .handler = &register_interval,
                                  .short_id = 'i',
                                  .long_id = "interval"},
    [OPT_FLOOD] = (t_opt_flag){.arg = ARG_NONE,
                               .handler = &register_flood,
                               .short_id = 'f',
                               .long_id = "flood"},
    [OPT_PRELOAD] = (t_opt_flag){.arg = ARG_REQUIRED,
                                 .handler = &register_preload,
                                 .short_id = 'l',
                                 .long_id = "preload"},
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
static int register_timeout(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > INT_MAX)
        ret = 1;
    if (ret != 0 || rslt == 0)
        ft_options_err_invalid_argument("timeout", arg, NULL);
    else {
        opt->timeout = (unsigned int)rslt;
        return (0);
    }
    return (2);
}
static int register_linger(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > INT_MAX)
        ret = 1;
    if (ret != 0 || rslt == 0)
        ft_options_err_invalid_argument("linger", arg, NULL);
    else {
        opt->linger_timeout = (unsigned int)rslt;
        return (0);
    }
    return (2);
}
static int register_identifier(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > INT_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("identifier", arg, NULL);
    else {
        opt->identifier = (unsigned int)rslt;
        return (0);
    }
    return (2);
}
static int register_numeric(t_options *opt, char *arg) {
    (void)arg;
    opt->numeric = true;
    return (0);
}
static int register_tos(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > UINT8_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("type-of-service", arg, NULL);
    else {
        opt->tos = (uint8_t)rslt;
        return (0);
    }
    return (2);
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
static int register_ignore_routing(t_options *opt, char *arg) {
    (void)arg;
    opt->ignore_routing = true;
    return (0);
}
static int register_interval(t_options *opt, char *arg) {
    float rslt = 0;
    int ret = 0;

    ret = ft_strtof(arg, &rslt, NULL);
    if (ret < 0.f)
        ft_options_err_invalid_argument("interval", arg, NULL);
    else {
        opt->interval = rslt;
        return (0);
    }
    return (2);
}
static int register_flood(t_options *opt, char *arg) {
    (void)arg;
    opt->flood = true;
    return (0);
}

int check_options(t_options *options) {
    if (options->flood && options->interval != -1.f)
        return (ft_options_err_incompatible_options("-f", "-i"));
    else if (options->interval == -1.f)
        options->interval = 1.f;
    return (0);
}
static int register_preload(t_options *opt, char *arg) {
    unsigned long rslt = 0;
    int ret = 0;

    ret = ft_strtoul_base(arg, &rslt, NULL, "0123456789");
    if (rslt > UINT32_MAX)
        ret = 1;
    if (ret != 0)
        ft_options_err_invalid_argument("preload", arg, NULL);
    else {
        opt->preload = (unsigned long)rslt;
        return (0);
    }
    return (2);
}