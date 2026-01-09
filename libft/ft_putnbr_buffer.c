#include <libft.h>

static void	put_nbr(char **s, long nb, size_t* nwrite, size_t size)
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

/// @brief Write ```nbr``` inside ```buffer``` of ```size``` bytes long.
/// @param nbr 
/// @param buffer 
/// @param size 
/// @return Number of characters written in buffer.
size_t	ft_putnbr_buffer(long nbr, char* buffer, size_t size) {
	size_t	nwrite = 0;

	if (nbr < 0 && size > 0) {
		buffer[nwrite++] = '-';
		buffer++;
		nbr = -nbr;
	}
	put_nbr(&buffer, nbr, &nwrite, size);
	return (nwrite);
}