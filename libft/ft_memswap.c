#include <libft.h>

/// @brief Swap 2 memory area using VLA (variable-length-array) and memcpy
/// @param a 
/// @param b 
/// @param size 
/// @note taken from https://stackoverflow.com/a/8166943
void	ft_memswap(void* a, void* b, size_t size) {
	union {
		int		i; //force alignment on 32 (or 64) bits to allow optimized memcpy
		char	tmp[size];
	} swap;

	ft_memcpy (swap.tmp, a, size);
	ft_memcpy (a, b, size);
	ft_memcpy (b, swap.tmp, size);
}
