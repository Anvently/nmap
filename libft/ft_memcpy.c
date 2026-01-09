/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/08 17:47:10 by npirard           #+#    #+#             */
/*   Updated: 2023/12/01 16:56:36 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

/// @brief Copy n bytes from memory address src to memory address dest.
/// The memory areas must not overlap.
/// @param dest Memory address
/// @param src  Memory address
/// @param n Number of byte to copy from src to dest
/// @return Memory area pointed by dest
void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	size_t	offset;

	if (n == 0 || dest == src)
		return (dest);
	for (offset = 0; offset < (n - (n % sizeof(long))); offset += sizeof(long))
		((long *) dest)[offset / sizeof(long)] = ((long *) src)[offset / sizeof(long)];
	for (;
		offset < n;
		offset += sizeof(unsigned char))
		((unsigned char *) dest)[offset] = ((unsigned char *) src)[offset];
	return (dest);
}
