#include <libft.h>

static size_t	len_nb(size_t len, long long nb)
{
	if (nb < 0)
	{
		nb = -nb;
		len++;
	}
	if (nb > 0)
		len = len_nb(len + 1, nb / 10);
	if (len > 0)
		return (len);
	else
		return (1);
}

static void	put_nbr(char **s, long long nb)
{
	if (nb < 0)
	{
		nb = -nb;
		**s = '-';
		*s = *s + 1;
	}
	if (nb >= 0 && nb <= 9)
	{
		**s = '0' + nb;
		*s = *s + 1;
	}
	else
	{
		put_nbr(s, nb / 10);
		put_nbr(s, nb % 10);
	}
}

/// @brief Return an allocated string representing n.
/// @param n Positive or negative long integer to convert.
/// @return String representing n. NULL if allocation fails.
char	*ft_ltoa(long n)
{
	char	*buffer;
	char	*index;
	size_t	size;

	size = len_nb(0, (long long)n);
	buffer = malloc(size + 1);
	if (!buffer)
		return (NULL);
	buffer[size] = '\0';
	index = buffer;
	put_nbr(&index, (long long) n);
	return (buffer);
}
