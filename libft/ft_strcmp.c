/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/11/08 17:57:34 by npirard           #+#    #+#             */
/*   Updated: 2023/12/01 16:56:36 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

/// @brief Compares s1 and s2 using ascii value of character.
/// @param s1 Null terminated string
/// @param s2 Null terminated string
/// @return difference between s1 and s2 where the first character differs
/// 0 if s1 and s2 are equal.
/// Negative value if s1 < s2.
/// Positive value if s1 > s2.
int	ft_strcmp(const char *s1, const char *s2)
{
	while (*s1 && *s1 == *s2)
	{
		s1++;
		s2++;
	}
	return ((unsigned char) *s1 - (unsigned char) *s2);
}

int	ft_stricmp(const char* s1, const char* s2) {
	while (*s1 && ft_tolower(*s1) == ft_tolower(*s2)) {
		s1++;
		s2++;
	}
	return ((unsigned char) ft_tolower(*s1) - (unsigned char) ft_tolower(*s2));
}

/// @brief Compare s1 and s2 using their ascii value.
/// @param s1 
/// @param s2 
/// @param ignore define a set of character that must be ignored from
/// the comparison, as if they were trimmed from the string
/// @return difference between s1 and s2 where the first character differs
/// 0 if s1 and s2 are equal.
/// Negative value if s1 < s2.
/// Positive value if s1 > s2.
int ft_strcmp_ignore(const char* s1, const char* s2, const char* ignore) {
	while (*s1 || *s2) {
		while (*s1 && ft_strchr(ignore, *s1) != NULL)
			s1++;
		while (*s2 && ft_strchr(ignore, *s2) != NULL)
			s2++;
		if (*s1 && *s1 == *s2) {
			s1++;
			s2++;
		} else
			break;
	}
	return ((unsigned char) *s1 - (unsigned char) *s2);
}

/// @brief Compare s1 and s2 using their ascii value but alphabetic comparison
/// are made insensitive to case.
/// @param s1 
/// @param s2 
/// @param ignore define a set of character that must be ignored from
/// the comparison, as if they were trimmed from the string. Characters are set
/// IS SENSITIVE to case.
/// @return difference between s1 and s2 where the first character differs
/// 0 if s1 and s2 are equal.
/// Negative value if s1 < s2.
/// Positive value if s1 > s2.
int ft_stricmp_ignore(const char* s1, const char* s2, const char* ignore) {
	while (*s1 || *s2) {
		while (*s1 && ft_strchr(ignore, *s1) != NULL)
			s1++;
		while (*s2 && ft_strchr(ignore, *s2) != NULL)
			s2++;
		if (*s1 && ft_tolower(*s1) == ft_tolower(*s2)) {
			s1++;
			s2++;
		} else
			break;
	}
	return ((unsigned char) ft_tolower(*s1) - (unsigned char) ft_tolower(*s2));
}

/// @brief Compares s1 and s2 using ascii value of character in reverse order;
/// @param s1 Null terminated string
/// @param s2 Null terminated string
/// @return difference between s1 and s2 where the first character differs
/// (starting from the end) . ```0``` if s1 and s2 are equal.
/// ```< 0``` if ```s1 < s2```.
/// ```> 0``` if ```s1 > s2```.
int	ft_strcmp_rev(const char *s1, const char *s2)
{
	size_t			i;
	size_t			len_s1;
	size_t			len_s2;
	unsigned char	c1 = 0, c2 = 0;

	i = 0;
	len_s1 = ft_strlen(s1);
	len_s2 = ft_strlen(s2);
	if (len_s1 && len_s2) {
		do {
			c1 = s1[len_s1 - i - 1];
			c2 = s2[len_s2 - i - 1];
		} while (++i && (len_s1 - i >= 1) && (len_s2 - i >= 1) && c1 == c2);
	}
	if (!(len_s1 && len_s2) || (c1 == c2)) {
		if (len_s1 - i == 0)
			c1 = 0;
		else
			c1 =  s1[len_s1 - i - 1];
		if (len_s2 - i == 0)
			c2 = 0;
		else
			c2 = s2[len_s2 - i - 1];
	}
	return ((unsigned char) c1 - (unsigned char) c2);
}

/// @brief Compares the firt n characters of s1
/// and s2 using ascii value of character.
/// @param s1 Null terminated string
/// @param s2 Null terminated string
/// @return difference between s1 and s2 where the first character differs
/// 0 if s1 and s2 are equal.
/// Negative value if s1 < s2.
/// Positive value if s1 > s2.
int	ft_strncmp(const char *s1, const char *s2, size_t n)
{
	size_t	i;

	i = 0;
	while (i < n && s1[i] && s2[i] && s1[i] == s2[i])
		i++;
	if (i == n)
		return (0);
	return ((unsigned char) s1[i] - (unsigned char) s2[i]);
}

/// @brief Compares the last n characters of s1
/// and s2 using ascii value of character.
/// @param s1 Null terminated string
/// @param s2 Null terminated string
/// @param n Number of characters to compare
/// @return difference between s1 and s2 where the first character differs
/// (starting from the end) . ```0``` if s1 and s2 are equal.
/// ```< 0``` if ```s1 < s2```.
/// ```> 0``` if ```s1 > s2```.
int	ft_strncmp_rev(const char *s1, const char *s2, size_t n)
{
	size_t			i;
	size_t			len_s1;
	size_t			len_s2;
	unsigned char	c1 = 0, c2= 0;

	i = 0;
	if (n == 0)
		return (0);
	len_s1 = ft_strlen(s1);
	len_s2 = ft_strlen(s2);
	if (len_s1 && len_s2) {
		do {
			c1 = s1[len_s1 - i - 1];
			c2 = s2[len_s2 - i - 1];
			i++;
		} while (i < n && (len_s1 - i >= 1) && (len_s2 - i >= 1) && c1 == c2);
	}
	if (!(len_s1 && len_s2) || (c1 == c2 && i < n)) {
		if (len_s1 - i == 0)
			c1 = 0;
		else
			c1 =  s1[len_s1 - i - 1];
		if (len_s2 - i == 0)
			c2 = 0;
		else
			c2 = s2[len_s2 - i - 1];
	}
	return ((unsigned char) c1 - (unsigned char) c2);
}

