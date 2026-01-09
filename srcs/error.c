#include <errno.h>
#include <libft.h>
#include <string.h>

extern const char *executable_name;

void error_unknown_host(const char *hostname) {
    ft_sdprintf(2, "%s: unknown host %s\n", executable_name, hostname);
}

void error_default(const char *hostname) {
    ft_sdprintf(2, "%s: %s: %s\n", executable_name, hostname, strerror(errno));
}