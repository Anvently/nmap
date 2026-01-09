#include <libft.h>

static t_vector_header*	_get_vector_header(const t_vector* vector) {
	if (vector == NULL)
		return (NULL);
	return (((t_vector_header*)vector) - 1);
}

/// @brief Realloc vector
/// @param vector_addr 
/// @param target_capacity 
/// @return ```1``` if allocation failed. Vector IS NOT freed
static int	_vector_realloc(t_vector** vector_addr, t_vector_header* header, size_t target_capacity) {
	t_vector_struct*	new_vector;

	new_vector = realloc(header,
		sizeof(t_vector_header) + target_capacity * header->type_size);
	if (!new_vector)
		return (1);
	if (new_vector != (t_vector_struct*)header)
		*vector_addr = &new_vector->data;
	new_vector->header.capacity = target_capacity;
	return (0);
}

// /// @brief Realloc vector by multiplying its capacity by 2
// /// If reallocation fails, vector IS NOT freed.
// /// @param vector_addr 
// /// @return ```1``` if allocation failed
// static int	_vector_expand(t_vector** vector_addr) {
// 	t_vector_header*	header;

// 	if (!*vector_addr)
// 		return (1);
// 	header = _get_vector_header(*vector_addr);
// 	return (_vector_realloc(vector_addr, header, (header->capacity ? header->capacity * 2 : 2)));
// }

// /// @brief Realloc vector by dividing its capacity by 2
// /// If reallocation fails, vector IS NOT freed.
// /// @param vector_addr 
// /// @return ```1``` if allocation failed
// static int	_vector_shrink(t_vector** vector_addr) {
// 	t_vector_header*	header;

// 	if (!*vector_addr)
// 		return (1);
// 	header = _get_vector_header(*vector_addr);
// 	return (_vector_realloc(vector_addr, header, (header->capacity ? header->capacity / 2 : 0)));
// }

static inline int	_has_capacity(t_vector_header* header) {
	return (header->capacity > header->len);
}

static inline int	_has_over_capacity(t_vector_header* header) {
	return (header->len < header->capacity / 4);
}

/// @brief Allocate a vector.
/// @param type_size Size in byte of vector elements
/// @param initial_capacity Number of element to reserve the space for at initialization
/// @return A pointer toward the vector data that can be used to access elements
/// ```NULL``` if allocation fails
t_vector*	ft_vector_create(size_t type_size, size_t initial_capacity) {
	t_vector_struct*			vector;

	vector = malloc(sizeof(t_vector_header) + type_size * initial_capacity);
	if (!vector)
		return (NULL);
	vector->header.capacity = initial_capacity;
	vector->header.type_size = type_size;
	vector->header.len = 0;
	return (&vector->data);
}

void			ft_vector_free(t_vector** vector_addr) {
	if (!*vector_addr)
		return;
	free(_get_vector_header(*vector_addr));
	*vector_addr = NULL;
}

/// @brief Add a new element to the vector which is a copy of memory area pointed
/// by data
/// @param vector_addr 
/// @param data 
/// @return ```1``` if a reallocation faield. Vector IS NOT freed
int			ft_vector_push(t_vector** vector_addr, const void* data) {
	t_vector_header*	header;
	
	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	return (ft_vector_insert_range(vector_addr, header->len, data, 1));
}

/// @brief Insert data at given pos in vector. Pos IS NOT checked.
/// @param vector_addr 
/// @param pos 
/// @param data 
/// @return ```1``` if ```vector_addr``` was ```NULL``` or if a realloc operation
/// failed. Vector IS NOT freed
int	ft_vector_insert(t_vector** vector_addr, size_t pos, const void* data) {
	return (ft_vector_insert_range(vector_addr, pos, data, 1));
}

int	ft_vector_push_range(t_vector** vector_addr, const void* data, size_t n) {
	t_vector_header*	header;
	
	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	return (ft_vector_insert_range(vector_addr, header->len, data, n));
}

/// @brief Remove the last element of the vector. Safe to use with an empty vector.
/// @param vector_addr 
/// @return ```1``` if ```vector_addr``` was ```NULL``` or if a shrinking operation
/// failed. Vector IS NOT freed. 
int	ft_vector_pop(t_vector** vector_addr) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	if (header->len == 0)
		return (0);
	return (ft_vector_erase_range(vector_addr, header->len - 1, 1));
}

int		ft_vector_pop_range(t_vector** vector_addr, size_t n) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	if (header->len == 0)
		return (0);
	return (ft_vector_erase_range(vector_addr, header->len - 1, n));
}

int		ft_vector_erase(t_vector** vector_addr, size_t pos) {
	return (ft_vector_erase_range(vector_addr, pos, 1));
}

int		ft_vector_erase_range(t_vector** vector_addr, size_t pos, size_t n) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	if (header->len == 0)
		return (0);
	else if (pos + 1 > header->len)
		*(int*)0 = 0; // We want to segfault when accessing non valid index
	if (pos + 1 != header->len)
		ft_memmove(*vector_addr + pos * header->type_size,
			*vector_addr + (pos + n) * header->type_size, header->len - (pos + 1));
	header->len -= n;
	if (_has_over_capacity(header)) {
		if (_vector_realloc(vector_addr, header, header->len * 2) == 1)
			return (1);
	}
	return (0);
}

/// @brief Insert a range of ```n``` element at index ```pos```. 
/// @param vector_addr 
/// @param pos 
/// @param data 
/// @param n 
/// @return ```1``` if ```vector_addr``` was ```NULL``` or if a realloc operation
/// failed. Vector IS NOT freed
int	ft_vector_insert_range(t_vector** vector_addr, size_t pos, const void* data, size_t n) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	if (pos > header->len)
		*(int*)0 = 0; // We want to segfault when accessing non valid index
	if (header->len + n > header->capacity) {
		if (_vector_realloc(vector_addr, header, (header->len + n) * 2) == 1)
			return (1);
		header = _get_vector_header(*vector_addr);
	}
	if (pos < header->len)
		ft_memmove(*vector_addr + (pos + n) * header->type_size,
			*vector_addr + pos * header->type_size, (header->len - pos) * header->type_size);
	ft_memcpy(*vector_addr + pos * header->type_size, data, header->type_size * n);
	header->len += n;
	return (0);
}

size_t	ft_vector_size(const t_vector* vector) {
	if (!vector)
		return (0);
	return (_get_vector_header(vector)->len);
}

/// @brief Set a vector capacity. Nothing is done if the actual size or capacity of the vector is
/// bigger than desired.
/// @param vector_addr 
/// @param nbr_el 
/// @return ```1``` if ```vector_addr``` was ```NULL``` or if a realloc operation
/// failed. Vector IS NOT freed
int	ft_vector_reserve(t_vector** vector_addr, size_t nbr_el) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	if (header->capacity > nbr_el)
		return (0);
	return (_vector_realloc(vector_addr, header, nbr_el));
}

/// @brief Force the vector for a new size. Vector is not necessarly shrinked.
/// @param vector_addr 
/// @param size 
/// @return 
int		ft_vector_resize(t_vector** vector_addr, size_t size) {
	t_vector_header*	header;

	if (!*vector_addr)
		return (1);
	header = _get_vector_header(*vector_addr);
	header->len = size;
	if (_has_over_capacity(header)) {
		if (_vector_realloc(vector_addr, header, header->len * 2) == 1)
			return (1);
	}
	return (0);
}

void	ft_vector_iter(t_vector *vector, void (*f)(void *))
{
	t_vector_header	*header;
	header = _get_vector_header(vector);
	if (!header)
		return;
	for (size_t i = 0; i < header->len; i++)
	{
		f(((char *)vector + i*header->type_size));
	}
}

void	ft_dump_vector(t_vector* vector, bool print_capacity) {
	t_vector_header*	header;

	header = _get_vector_header(vector);
	if (!header) {
		ft_printf("(null)\n");
		return;
	}
	ft_printf("size = %d/%d | type_size = %y\n", header->len, header->capacity, header->type_size);
	ft_hexdump_color_zone(vector, (print_capacity ? header->capacity : header->len) * header->type_size,
		1, 0, header->type_size);
}


