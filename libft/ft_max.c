/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_max.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/12/05 15:02:07 by npirard           #+#    #+#             */
/*   Updated: 2024/02/21 13:13:42 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

unsigned long ft_min_lu(unsigned long a, unsigned long b) {
    if (a < b)
        return (a);
    return (b);
}

unsigned long ft_max_lu(unsigned long a, unsigned long b) {
    if (a > b)
        return (a);
    return (b);
}

unsigned int ft_min_u(unsigned int a, unsigned int b) {
    if (a < b)
        return (a);
    return (b);
}

unsigned int ft_max_u(unsigned int a, unsigned int b) {
    if (a > b)
        return (a);
    return (b);
}

long ft_min_ld(long a, long b) {
    if (a < b)
        return (a);
    return (b);
}

long ft_max_ld(long a, long b) {
    if (a > b)
        return (a);
    return (b);
}

int ft_min_i(int a, int b) {
    if (a < b)
        return (a);
    return (b);
}

int ft_max_i(int a, int b) {
    if (a > b)
        return (a);
    return (b);
}