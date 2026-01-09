#include <libft.h>

static void	put_nbr(char **s, unsigned long nb, size_t* nwrite, size_t size)
{
	if (*nwrite >= size)
		return;
	if (nb <= 9)
	{
		**s = '0' + nb;
		*s = *s + 1;
		(*nwrite)++;
	}
	else
	{
		put_nbr(s, nb / 10, nwrite, size);
		put_nbr(s, nb % 10, nwrite, size);
	}

}

static void	put_nbr_base(char **s, unsigned long nb, size_t* nwrite, size_t size, const char* base, size_t len_base)
{
	if (*nwrite >= size)
		return;
	if (nb <= len_base - 1)
	{
		**s = base[nb];
		*s = *s + 1;
		(*nwrite)++;
	}
	else
	{
		put_nbr_base(s, nb / len_base, nwrite, size, base, len_base);
		put_nbr_base(s, nb % len_base, nwrite, size, base, len_base);
	}

}

size_t	ft_putunbr_base_buffer(unsigned long nbr, char* buffer, size_t size, const char* base) {
	size_t	nwrite = 0;

	put_nbr_base(&buffer, nbr, &nwrite, size, base, ft_strlen(base));
	return (nwrite);
}

size_t	ft_putunbr_buffer(unsigned long nbr, char* buffer, size_t size) {
	size_t	nwrite = 0;

	put_nbr(&buffer, nbr, &nwrite, size);
	return (nwrite);
}