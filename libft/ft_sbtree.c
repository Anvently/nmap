#include <libft.h>

static int	default_cmp(const void* a, const void* b) {
	return (a - b);
}

/// @brief Return ptr address toward the smallest node of the tree
/// @param root 
/// @return 
static t_sbtree**	_ft_sbtree_min_ptr(t_sbtree** root) {
	while ((*root)->left)
		return (_ft_sbtree_min_ptr(&(*root)->left));
	return (root);
}

/// @brief Debug purpose. Return ```true``` if the tree is correctly sorted else ```false```.
/// @param root 
/// @param cmp 
/// @return 
bool	ft_sbtree_check_consistency(t_sbtree* root, int (*cmp)(const void*, const void*)) {
	if (root == NULL)
		return (true);
	if (cmp == NULL)
		cmp = &default_cmp;
	if (root->right) {
		if ((*cmp)(root->data, root->right->data) > 0) {
			ft_sdprintf(2, "failed at %p vs %p\n", root->data, root->right->data);
			return (false);
		}
		if (ft_sbtree_check_consistency(root->right, cmp) == false)
			return (false);
	}
	if (root->left) {
		if ((*cmp)(root->data, root->left->data) < 0) {
			ft_sdprintf(2, "failed at %p vs %p\n", root->data, root->right->data);
			return (false);
		}
		if (ft_sbtree_check_consistency(root->left, cmp) == false)
			return (false);
	}
	return (true);
}

/// @brief Recursively replace parent with the child having the longest branch
/// @param parent 
__attribute_maybe_unused__
static void	ft_sbtree_rotate_longest(t_sbtree** parent) {
		// t_sbtree*	orphan;
		t_sbtree*	node;

		if (*parent == NULL)
			return;
		node = *parent;
		if (ft_sbtree_shortest(*parent) <= 0) { //Left rotate
			// orphan = (*parent)->left;
			*parent = (*parent)->right;
			ft_sbtree_rotate_longest(&node->right);
			if (*parent) {
				(*parent)->left = node->left;
				(*parent)->right = node->right;
			}
		} else { //Right rotate
			// orphan = (*parent)->right;
			*parent = (*parent)->left;
			ft_sbtree_rotate_longest(&node->left);
			if (*parent) {
				(*parent)->right = node->right;
				(*parent)->left = node->left;
			}
		}
}

/// @brief Recursively insert a node in a sbtree starting from given root ```parent```.
/// @param parent addr of pointer storing the link toward the parent root. If ```NULL```
/// the recursion will stopped here and a new node will be inserted at this address.
/// @param data Can be either a integral type or the adress of a structure. 
/// @param cmp If ```NULL``` data will be compared as integral type. If a function is given
/// they will be passed as adress toward a memory area.
/// @return ```0``` if the node was inserted. ```ERROR_FATAL(-1)``` if allocation error,
/// ```1``` if data to insert is a  doubloon.
int	ft_sbtree_insert(t_sbtree** parent, const void* data, int (*cmp)(const void*, const void*)) {
	t_sbtree*	new_node;
	int			diff;

	if (cmp == NULL)
		cmp = &default_cmp;
	if (*parent == NULL) {
		new_node = ft_calloc(1, sizeof(t_sbtree));
		if (new_node == NULL)
			return (ERROR_FATAL);
		new_node->data = (void*) data;
		*parent = new_node;
		return (0);
	}
	diff = (*cmp)((*parent)->data, data);
	if (diff < 0)
		return (ft_sbtree_insert(&(*parent)->right, data, cmp));
	else if (diff > 0)
		return (ft_sbtree_insert(&(*parent)->left, data, cmp));
	else
		return (1);
}

/// @brief Return the smallest node of the tree
/// @param root 
/// @return 
const t_sbtree*	ft_sbtree_min_node(const t_sbtree* root) {
	while (root->left)
		return (ft_sbtree_min_node(root->left));
	return (root);
}

const void*	ft_sbtree_min(const t_sbtree* root) {
	const t_sbtree*	node = ft_sbtree_min_node(root);
	return (node ? node->data : NULL);
}

/// @brief Return the greatest node of the tree
/// @param root 
/// @return 
const t_sbtree*	ft_sbtree_max_node(const t_sbtree* root) {
	while (root->right)
		return (ft_sbtree_max_node(root->right));
	return (root);
}

const void*	ft_sbtree_max(const t_sbtree* root) {
	const t_sbtree*	node = ft_sbtree_max_node(root);
	return (node ? node->data : NULL);
}

/// @brief Return node where ```(*cmp)(node->data, data) == 0``` if any
/// else return ```NULL```
/// @param root 
/// @param data 
/// @param cmp 
/// @return 
const t_sbtree*	ft_sbtree_find_node(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	int	diff;

	if (root == NULL)
		return (NULL);
	if (cmp == NULL)
		cmp = default_cmp;
	diff = (*cmp)(root->data, data);
	if (diff == 0)
		return (root);
	if (diff < 0)
		return (ft_sbtree_find_node(root->right, data, cmp));
	return (ft_sbtree_find_node(root->left, data, cmp));
}

const void*		ft_sbtree_find(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	const t_sbtree*	node = ft_sbtree_find_node(root, data, cmp);
	return (node ? node->data : NULL);
}

/// @brief Return the greatest node of the tree where ```(*cmp)(node->data, data) < 0``` if any
/// else return ```NULL```
/// @param root 
/// @param data 
/// @param cmp 
/// @return 
const t_sbtree*	ft_sbtree_lower_bound_node(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	const t_sbtree*	node;
	int				diff;

	if (root == NULL)
		return (NULL);
	if (cmp == NULL)
		cmp = default_cmp;
	diff = (*cmp)(root->data, data);
	if (diff == 0)
		return (root->left ? ft_sbtree_max_node(root->left) : NULL);
	if (diff < 0) {
		node = ft_sbtree_lower_bound_node(root->right, data, cmp);
		return (node ? node : root);
	} else {
		return (ft_sbtree_lower_bound_node(root->left, data, cmp));
	}
}

const void*		ft_sbtree_lower_bound(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	const t_sbtree*	node = ft_sbtree_lower_bound_node(root, data, cmp);
	return (node ? node->data : NULL);
}

/// @brief Return the smallest node of the tree where ```(*cmp)(node->data, data) > 0``` if any
/// else return ```NULL```
/// @param root 
/// @param data 
/// @param cmp 
/// @return 
const t_sbtree*	ft_sbtree_upper_bound_node(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	const t_sbtree*	node;
	int				diff;

	if (root == NULL)
		return (NULL);
	if (cmp == NULL)
		cmp = default_cmp;
	diff = (*cmp)(root->data, data);
	if (diff == 0)
		return (root->right ? ft_sbtree_max_node(root->right) : NULL);
	if (diff > 0) {
		node = ft_sbtree_upper_bound_node(root->left, data, cmp);
		return (node ? node : root);
	} else 
		return (ft_sbtree_upper_bound_node(root->right, data, cmp));
}

const void*		ft_sbtree_upper_bound(const t_sbtree* root, const void* data, int (*cmp)(const void*, const void*)) {
	const t_sbtree*	node = ft_sbtree_upper_bound_node(root, data, cmp);
	return (node ? node->data : NULL);
}

/// @brief Recursively remove a given node. 
/// @param node_ptr 
/// @return The node that was removed, that can be passed to free.
/// Same as ```*node_ptr```
t_sbtree*	ft_sbtree_pop_node(t_sbtree** node_ptr) {
	t_sbtree	*tmp, *node;
	t_sbtree**	upper_bound;

	node = *node_ptr;
	if (node == NULL)
		return (NULL);
	if (node->left && node->right) {
		upper_bound = _ft_sbtree_min_ptr(&(*node_ptr)->right);
		if (&(*node_ptr)->right == upper_bound) { // rotate adjacent node
			tmp = (*node_ptr)->left;
			(*node_ptr)->left = (*upper_bound)->left;
			(*upper_bound)->left = tmp;
			tmp = *upper_bound;
			(*node_ptr)->right = (*upper_bound)->right;
			tmp->right = *node_ptr;
			*node_ptr = tmp;
			ft_sbtree_pop_node(&(*node_ptr)->right);
		} else { 
			tmp = (*upper_bound)->left;
			(*upper_bound)->left = (*node_ptr)->left;
			(*node_ptr)->left = tmp;
			tmp = (*upper_bound)->right;
			(*upper_bound)->right = (*node_ptr)->right;
			(*node_ptr)->right = tmp;
			tmp = (*node_ptr);
			*node_ptr = *upper_bound;
			*upper_bound = node;
			ft_sbtree_pop_node(upper_bound);
		}
	}
	else if (node->left)
		*node_ptr = node->left;
	else if (node->right)
		*node_ptr = node->right;
	else
		*node_ptr = NULL;
	return (node);
}

/// @brief Remove node containing ```data``` if found.
/// @param parent 
/// @param node 
/// @param cmp 
/// @return ```0``` if a node was deleted. ```1``` if no node containing
//// ```data``` was found.
int	ft_sbtree_remove(t_sbtree** root, const void* data, int (*cmp)(const void*, const void*), void (*free_fun)(void *)) {
	t_sbtree*	node;
	int			diff;

	if (cmp == NULL)
		cmp = &default_cmp;
	if (*root == NULL)
		return (1);
	diff = (*cmp)((*root)->data, data);
	if (diff == 0) {
		node = ft_sbtree_pop_node(root);
		if (free_fun)
			(*free_fun)(node->data);
		free(node);
		return (0);
	} else if (diff < 0)
		return (ft_sbtree_remove(&(*root)->right, data, cmp, free_fun));
	else if (diff > 0)
		return (ft_sbtree_remove(&(*root)->left, data, cmp, free_fun));
	return (0);
}

/// @brief Identify the shortest branch in the tree (in height) starting from ```root```
/// @param root 
/// @return ```-1``` if left branch is shorter. ```1``` if right branch is shorter.
/// ```0``` if branch are equal in height
int			ft_sbtree_shortest(const t_sbtree* root) {
	size_t	len_r = ft_sbtree_height(root->right, 0);
	size_t	len_l = ft_sbtree_height(root->left, 0);
	if (len_l == len_r)
		return (0);
	if (len_l < len_r)
		return (-1);
	return (1);
}

size_t	ft_sbtree_height(const t_sbtree* root, int height) {
	size_t	r_height = 0;
	size_t	l_height = 0;

	if (root == NULL)
		return (height);
	r_height = ft_sbtree_height(root->right, height + 1);
	l_height = ft_sbtree_height(root->left, height + 1);
	return (l_height >= r_height ? l_height : r_height);
}

void	ft_sbtree_clear(t_sbtree* root, void (*free_func)(void*)) {
	if (root == NULL)
		return;
	ft_sbtree_clear(root->left, free_func);
	ft_sbtree_clear(root->right, free_func);
	if (free_func && root->data)
		(*free_func)(root->data);
	free(root);
}

/// @brief Return the number of element inside the tree
/// @param root 
/// @return 
size_t	ft_sbtree_size(const t_sbtree* root) {
	size_t	size;

	if (root == NULL)
		return (0);
	size = 1;
	size += ft_sbtree_size(root->right);
	size += ft_sbtree_size(root->left);
	return (size);
}

#define		_ft_sbtree_print_call(fun, data) ((fun) ? ((fun)(data)) : ft_sdprintf(1, "%p\n", (data)))

void	_ft_sbtree_print(const t_sbtree* tree, int level, void (*fun)(const void*)) {
	static char			padding[128];

	if (tree == NULL)
		return;
	if (level == 0)
		ft_memset(&padding[0], 0, sizeof(padding));
	_ft_sbtree_print_call(fun, tree->data);
	// ft_sdprintf(1, "%p\n", tree->data);
	if (tree->right && tree->left) {
		ft_sdprintf(1, "%s├─ ", padding);
		ft_strlcat(&padding[0], "|  ", sizeof(padding));
		_ft_sbtree_print(tree->right, level + 1, fun);
		padding[ft_strlen(padding) - 3] = '\0';
		ft_sdprintf(1, "%s└─ ", padding);
		ft_strlcat(&padding[0], "   ", sizeof(padding));
		_ft_sbtree_print(tree->left, level + 1, fun);
		padding[ft_strlen(padding) - 3] = '\0';
	}
	else if (tree->right) {
		ft_sdprintf(1, "%s└─ ", padding);
		ft_strlcat(&padding[0], "   ", sizeof(padding));
		_ft_sbtree_print(tree->right, level + 1, fun);
		padding[ft_strlen(padding) - 3] = '\0';
	}
	else if (tree->left) {
		ft_sdprintf(1, "%s|\n", padding);
		ft_sdprintf(1, "%s└─ ", padding);
		ft_strlcat(&padding[0], "   ", sizeof(padding));
		_ft_sbtree_print(tree->left, level + 1, fun);
		padding[ft_strlen(padding) - 3] = '\0';
	}
}
