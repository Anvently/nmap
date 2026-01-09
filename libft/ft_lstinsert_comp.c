#include <libft.h>

/// @brief Insert ```node``` in ```list``` before the first element where
/// ```comp(node->content, element->content) <= 0``` 
/// @param list 
/// @param node 
/// @param comp 
/// @param reverse enable descending sort
void	ft_lstinsert_comp(t_list** list, t_list* node, int (*comp)(void*, void*), bool reverse) {
	t_list*	current;

	if (node == NULL || list == NULL)
		return;
	if (*list == NULL || (((*comp)(node->content, (*list)->content) * (reverse ? -1 : 1)) <= 0)) {
		ft_lstadd_front(list, node);
		return;
	}
	current = *list;
	while (current) {
		if (current->next == NULL || (((*comp)(node->content, current->next->content) * (reverse ? -1 : 1)) <= 0)) {
			ft_lstmerge(current, &node);
			return ;
		}
		current = current->next;
	}
}

/// 2 - 6 - 13 - 14 - 15
