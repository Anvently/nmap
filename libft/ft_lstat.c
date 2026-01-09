#include <libft.h>

/// @brief Return list element at given index
/// @param list 
/// @param index 
/// @return 
t_list*	ft_lstat(t_list* list, const unsigned int index) {
	unsigned int i = 0;
	while (list && i != index) {
		i++;
		list = list->next;
	}
	return (list);
}
