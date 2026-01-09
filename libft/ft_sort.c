#include <libft.h>

/// @brief Insertion sort implementation.
/// @param range 
/// @param len 
/// @param el_size 
/// @param cmp ```a``` and ```b``` are passed by address and not by copy
void	_ft_insertion_sort(void* range, size_t len, size_t el_size, int (*cmp)(void* a, void* b), bool rev) {
	size_t	sorted_len = 1;
	size_t	i;

	while (sorted_len < len) {
		i = sorted_len;
		while (1) {
			if ((*cmp)(range + el_size * i, range + el_size * (i - 1)) * (rev ? -1 : 1) < 0)
				ft_memswap(range + el_size * i, range + el_size * (i - 1), el_size);
			else
				break;
			if (--i == 0)
				break;
		}
		sorted_len++; 
	}
}

static int	_ft_merge(void* range, size_t len1, size_t len2, size_t el_size, int (*cmp)(void* a, void* b), bool rev) {
	void	*tmp1, *tmp2;
	size_t	i, j, k = 0;

	// Allocate and copy temp array in order to merge range in place
	tmp1 = malloc(len1 * el_size);
	tmp2 = malloc(len2 * el_size);
	if (!tmp1 || !tmp2) {
		free(tmp1);
		free(tmp2);
		return (1);
	}
	ft_memcpy(tmp1, range, len1 * el_size);
	ft_memcpy(tmp2, range + len1 * el_size, len2 * el_size);

	for (i = 0, j = 0; i < len1 && j < len2;) {
		if ((*cmp)(tmp1 + i * el_size, tmp2 + j * el_size) * (rev ? -1 : 1) < 0)// IF *tmp1 < *tmp2
			ft_memcpy(range + (k++ * el_size), tmp1 + i++ * el_size, el_size);
		else
			ft_memcpy(range + (k++ * el_size), tmp2 + j++ * el_size, el_size);
	}

	// If something remains in tmp1 or tmp2, we can make a single memcpy
	if (i < len1) {
		ft_memcpy(range + (k * el_size), tmp1 + i * el_size, (len1 - i) * el_size);
	}

	if (j < len2) {
		ft_memcpy(range + (k * el_size), tmp2 + j * el_size, (len2 - j) * el_size);
	}

	free(tmp1);
	free(tmp2);

	return (0);
}

/// @brief Merge sort implementation. Merging is done inplace. So any failed
/// allocation will result in an unfinished sorted.
/// @param range 
/// @param len number of element in the array
/// @param el_size Size of each element in the array, in bytes
/// @param cmp ```a``` and ```b``` are passed by address and not by copy
/// @param rev reverse sort
/// @return 
int	_ft_merge_sort(void* range, size_t len, size_t el_size, int (*cmp)(void* a, void* b), bool rev) {
	int	middle;

	// If size == 1, return
	if (len <= 1) return (0);

	// Divide array by 2
	middle = len / 2;
	if (_ft_merge_sort(range, len / 2 + (len % 2), el_size, cmp, rev)) // index are put in first array
		return (1);
	if (_ft_merge_sort(range + (middle + len % 2) * el_size, len / 2, el_size, cmp, rev))
		return (1);
	if (_ft_merge(range, middle + (len % 2), len / 2, el_size, cmp, rev))
		return (1);
	return (0);
}
