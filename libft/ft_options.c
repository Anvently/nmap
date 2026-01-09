#include <libft.h>

// NBR_OPTIONS must be defined as the size of options_map
extern int NBR_OPTIONS;
extern t_opt_flag *options_map;
extern const char *executable_name;

static int print_valid_arguments(const char ***valids) {
    if (!valids || !*valids)
        return (0);
    ft_dprintf(2, "Valid arguments are:\n");
    for (int i = 0; valids[i]; i++) {
        write(2, "  - ", 4);
        for (int j = 0; valids[i][j]; j++) {
            ft_dprintf(2, "‘%s’%s", valids[i][j],
                       (valids[i][j + 1] ? ", " : ""));
        }
        write(2, "\n", 1);
    }
    return (0);
}

static int error_invalid_flag(const char flag) {
    ft_dprintf(2, "%s: invalid option -- '%c'\n", executable_name, flag);
    return (ERROR_INPUT);
}

static int error_invalid_option(const char *arg) {
    ft_dprintf(2, "%s: unrecognised option '--%s'\n", executable_name, arg);
    return (ERROR_INPUT);
}

static int error_ambiguous_option(const char *arg, t_list *matches) {
    ft_dprintf(2, "%s: option '--%s' is ambiguous; possibilities: ",
               executable_name, arg);
    while (matches) {
        ft_dprintf(2, " '--%s'", ((t_opt_flag *)matches->content)->long_id);
        matches = matches->next;
    }
    write(2, "\n", 1);
    return (ERROR_INPUT);
}

static int error_flag_missing_argument(const char option) {
    ft_dprintf(2, "%s: option requires an argument -- '%c'\n", executable_name,
               option);
    return (ERROR_INPUT);
}

static int error_option_missing_argument(const char *option) {
    ft_dprintf(2, "%s: option '--%s' requires an argument\n", executable_name,
               option);
    return (ERROR_INPUT);
}

static int error_option_extra_argument(const char *option, int end) {
    ft_dprintf(2, "%s: option '--%.*s' doesn't allow an argument\n",
               executable_name, end, option);
    return (ERROR_INPUT);
}

int ft_options_err_invalid_argument(const char *option, const char *arg,
                                    const char ***valids) {
    ft_dprintf(2, "%s: invalid argument ‘%s’ for ‘--%s’\n", executable_name,
               arg, option);
    print_valid_arguments(valids);
    return (ERROR_INPUT);
}

int ft_options_err_ambiguous_argument(const char *option, const char *arg,
                                      const char ***valids) {
    ft_dprintf(2, "%s: ambiguous argument ‘%s’ for ‘--%s’\n", executable_name,
               arg, option);
    print_valid_arguments(valids);
    return (ERROR_INPUT);
}

int ft_options_err_incompatible_options(const char *option1,
                                        const char *option2) {
    ft_dprintf(2, "%s: incompatible options ‘%s’ and ‘%s’\n", executable_name,
               option1, option2);
    return (ERROR_INPUT);
}

/// @brief Parse a short flag in the form and enable it
/// @param arg
/// @param options
/// @return ```2``` if unknown flag. ```-1``` if no error but what's remaining
/// in arg should be considered as option argument and thus ignored.
static int ft_parse_arg_short(char **next_arg, char *option,
                              t_options *options) {
    t_opt_flag *flag_info = NULL;
    int ret = 0;

    if (*option == '\0')
        return (0);
    for (int i = 0; i < NBR_OPTIONS; i++) {
        if (options_map[i].short_id == *option) {
            flag_info = &options_map[i];
            break;
        }
    }
    if (flag_info == NULL)
        return (error_invalid_flag(*option));
    if (flag_info->arg) {
        if (option[1] == '\0') {
            if (flag_info->arg == ARG_REQUIRED) {
                if (next_arg == NULL)
                    return (error_flag_missing_argument(*option));
                ret = (*flag_info->handler)(options, *next_arg);
                *next_arg = NULL;
                return (ret);
            }
            ret = (*flag_info->handler)(options, NULL);
        }
        ret = (*flag_info->handler)(options, option + 1);
        if (ret)
            return (ret);
        return (-1);
    }
    return ((*flag_info->handler)(options, NULL));
}

static int ft_parse_flag_list(char **next_arg, char *arg, t_options *options) {
    int ret = 0;

    for (int i = 0; arg[i]; i++) {
        ret = ft_parse_arg_short(next_arg, arg + i, options);
        if (ret > 0)
            return (ERROR_INPUT);
        if (ret < 0)
            break;
    }
    return (0);
}

static int ft_option_long_handle_arg(char **next_arg, t_opt_flag *flag_info,
                                     char *option, size_t end,
                                     t_options *options) {
    int ret = 0;

    if (option[end] == '\0') {
        if (flag_info->arg == ARG_REQUIRED) {
            if (next_arg == NULL)
                return (error_option_missing_argument(flag_info->long_id));
            ret = (*flag_info->handler)(options, *next_arg);
            *next_arg = NULL;
            return (ret);
        }
        return ((*flag_info->handler)(options, NULL));
    }
    if (flag_info->arg == ARG_NONE)
        return (error_option_extra_argument(option, end));
    return ((*flag_info->handler)(options, option + end + 1));
}

/// @brief
/// @param arg
/// @param options
/// @return ```-1``` if allocation error.
/// ```2``` of input error
static int ft_parse_option_long(char **next_arg, char *arg,
                                t_options *options) {
    t_list *matches = NULL, *node;
    size_t end;
    int ret = 0;

    for (end = 0; arg[end] && arg[end] != '='; end++)
        ;
    for (int i = 0; i < NBR_OPTIONS; i++) {
        if (options_map[i].long_id == NULL)
            continue;
        if (ft_strncmp(arg, options_map[i].long_id, end) == 0) {
            node = ft_lstnew(&options_map[i]);
            if (node == NULL) {
                ft_lstclear(&matches, NULL);
                return (ERROR_FATAL);
            }
            ft_lstadd_back(&matches, node);
        }
    }
    if (matches == NULL)
        ret = error_invalid_option(arg);
    else if (matches->next != NULL)
        ret = error_ambiguous_option(arg, matches);
    else
        ret = ft_option_long_handle_arg(
            next_arg, (t_opt_flag *)matches->content, arg, end, options);
    ft_lstclear(&matches, NULL);
    return (ret);
}

int check_options(t_options *options) { return (0); }

/// @brief Extract options in ```args``` and replaced them with ```NULL```.
/// @param nbr
/// @param args
/// @param options
/// @param arg_number if given, will receive nuber of non-options argument
/// @return ```2``` if input error
/// ```-1``` if allocatio error
int ft_options_retrieve(int nbr, char **args, t_options *options,
                        unsigned int *arg_number) {
    int ret = 0;

    if (arg_number)
        *arg_number = 0;
    for (int i = 0; i < nbr; i++) {
        if (args[i] == NULL)
            continue;
        if (args[i][0] == '-') {
            if (args[i][1] == '-' && (ft_isspace(args[i][2]) || !args[i][2])) {
                args[i] = NULL;
                break;
            } else if (args[i][1] == '-') {
                if ((ret = ft_parse_option_long(
                         (i + 1 == nbr ? NULL : &args[i + 1]), args[i] + 2,
                         options)))
                    return (ret);
            } else {
                if ((ret = ft_parse_flag_list(
                         (i + 1 == nbr ? NULL : &args[i + 1]), args[i] + 1,
                         options)))
                    return (ret);
            }
            args[i] = NULL;
        } else if (arg_number) {
            (*arg_number)++;
        }
    }
    return (check_options(options));
}
