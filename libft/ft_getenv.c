/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   env.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/05 16:06:33 by npirard           #+#    #+#             */
/*   Updated: 2024/01/30 11:41:38 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>
#include <errno.h>

/// @brief Look for a given variable in env and return it as a new allocated
/// string
/// @param var Name of the variable to find (without $)
/// @param env
/// @return Allocated string. If variable isn't found, return empty string.
/// ```NULL``` if allocation error.
char	*ft_getenv(char *var, char **env)
{
	char	*var_value;
	size_t	len_var;

	if (!var)
		return (NULL);
	len_var = ft_strlen(var);
	while (*env)
	{
		if (!ft_strncmp(*env, var, len_var))
			if ((*env)[len_var] == '=')
				break ;
		env++;
	}
	if (*env)
		var_value = ft_substr(*env, len_var + 1,
				ft_strlen(*env) - len_var + 1);
	else
		var_value = ft_strdup("");
	if (!var_value)
		return (alloc_error());
	return (var_value);
}
