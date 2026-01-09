/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/08 17:46:27 by npirard           #+#    #+#             */
/*   Updated: 2023/12/01 16:56:36 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

/// @brief Fill n bytes of given memory address pointed by s with given c byte.
/// @param s Address to fill
/// @param c Value to fill address with
/// @param n Number of byte to fill
/// @return s memory address
void	*ft_memset(void *s, int c, size_t n)
{
	char	value64[sizeof(long)] = {c, c, c, c, c, c, c, c};
	size_t	offset;

	if (n == 0)
		return (s);
	for (offset = 0; offset < (n / sizeof(long)); offset += sizeof(long))
		((long *) s)[offset / sizeof(long)] = *(long *)&value64[0];
	for (;
		offset < (sizeof(long) * (n / sizeof(long)) + (n % sizeof(long)));
		offset += sizeof(unsigned char))
		((unsigned char *) s)[offset] = c;
	return (s);
}

// void	*ft_memcpy(void *dest, const void *src, size_t n)
// {
// 	size_t	offset;

// 	if (n == 0 || dest == src)
// 		return (dest);
// 	for (offset = 0; offset < (n / sizeof(long)); offset += sizeof(long))
// 		((long *) dest)[offset / sizeof(long)] = ((long *) src)[offset / sizeof(long)];
// 	for (offset;
// 		offset < (sizeof(long) * (n / sizeof(long)) + (n % sizeof(long)));
// 		offset += sizeof(unsigned char))
// 		((unsigned char *) dest)[offset] = ((unsigned char *) src)[offset];
// 	return (dest);
// }

