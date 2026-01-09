#include <libft.h>

/// @brief Remove the first element of the list and assign
/// the next element as the new list's head.
/// @param list 
/// @param del 
void	ft_lstpop_front(t_list** list, void (*del)(void *)) {
	if (!list || *list == NULL)
		return ;
	t_list*	next = (*list)->next;
	ft_lstdelone(*list, del);
	*list = next;
}
