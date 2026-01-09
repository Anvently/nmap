/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: npirard <npirard@student.42.fr>            +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2023/09/19 09:23:38 by npirard           #+#    #+#             */
/*   Updated: 2024/02/21 13:14:12 by npirard          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
#define LIBFT_H

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 1000
#elif BUFFER_SIZE < 0
#undef BUFFER_SIZE
#define BUFFER_SIZE 1000
#endif

#ifndef __FT_ERRORS
#define __FT_ERRORS
enum E_ERRORS { ERROR_FATAL = -1, SUCCESS = 0, ERROR_SYS = 1, ERROR_INPUT = 2 };
#endif

#define TERM_CL_RED "\033[31m"
#define TERM_CL_GREEN "\033[32m"
#define TERM_CL_YELLOW "\033[33m"
#define TERM_CL_BLUE "\033[34m"
#define TERM_CL_MAGENTA "\033[35m"
#define TERM_CL_CYAN "\033[36m"
#define TERM_CL_WHITE "\033[37m"
#define TERM_CL_RESET "\033[0m"
#define TERM_CL_BK_GREEN "\033[42m"
#define TERM_CL_BK_RED "\033[41m"
#define TERM_CL_BOLD "\033[1m"

/* ---------------------------------- MATH ---------------------------------- */

int ft_abs(int n);
int ft_imax(int a, int b); /// DEPRECATED
double ft_dmax(double a, double b);
void *ft_max(void *a, void *b, size_t size); /// DEPRECATED
void *ft_min(void *a, void *b, size_t size); /// DEPRECATED
int ft_min_i(int a, int b);
int ft_max_i(int a, int b);
unsigned int ft_min_u(unsigned int a, unsigned int b);
unsigned int ft_max_u(unsigned int a, unsigned int b);
unsigned long ft_min_lu(unsigned long a, unsigned long b);
unsigned long ft_max_lu(unsigned long a, unsigned long b);
long ft_min_ld(long a, long b);
long ft_max_ld(long a, long b);

///------------------------ CHAR TEST -----------------------------

int ft_isalpha(int c);
int ft_isdigit(int c);
int ft_isalnum(int c);
int ft_isascii(int c);
int ft_isprint(int c);
int ft_isspace(char c);

///------------------------ CHAR CONVERSION ------------------------

int ft_toupper(int c);
int ft_tolower(int c);

///------------------------ STRING EDITION ------------------------

size_t ft_strlen(const char *s);
size_t ft_strlcpy(char *dst, const char *src, size_t size);
size_t ft_strlcat(char *dst, const char *src, size_t size);
char *ft_strdup(const char *s);
char *ft_substr(char const *s, unsigned int start, size_t len);
char *ft_strjoin(char const *s1, char const *s2);
char *ft_strjoin2(char const *s1, char const *s2);
char *ft_strtrim(char const *s1, char const *set);

///----------------------- STRING TEST -------------------------

char *ft_strchr(const char *s, int c);
char *ft_strrchr(const char *s, int c);
char *ft_strnstr(const char *big, const char *little, size_t len);
int ft_strcmp(const char *s1, const char *s2);
int ft_strcmp_rev(const char *s1, const char *s2);
int ft_strncmp(const char *s1, const char *s2, size_t n);
int ft_strncmp_rev(const char *s1, const char *s2, size_t n);
int ft_stricmp(const char *s1, const char *s2);
int ft_strcmp_ignore(const char *s1, const char *s2, const char *ignore);
int ft_stricmp_ignore(const char *s1, const char *s2, const char *ignore);
void *ft_memchr(const void *s, int c, size_t n);
int ft_memcmp(const void *s1, const void *s2, size_t n);
bool ft_isupper(int c);
bool ft_islower(int c);

///------------------------------ MEM --------------------------

void *ft_memset(void *s, int c, size_t n);
void ft_bzero(void *s, size_t n);
void *ft_memcpy(void *dest, const void *src, size_t n);
void *ft_memmove(void *dest, const void *src, size_t n);
void ft_memswap(void *a, void *b, size_t size);
void *ft_calloc(size_t nmenb, size_t size);
void ft_hexdump(const void *addr, size_t n, size_t unit, size_t offset);
void ft_hexdump_color_zone(const void *addr, size_t n, size_t unit,
                           size_t start_from, size_t len_zone);

/* --------------------------------- STRINGS -------------------------------- */

char **ft_split(char const *s, char c);
char **ft_free_strs(char **strings);
char ***ft_free_strss(char ***strs);
int ft_strslen(char **strs);
int ft_strsslen(char ***strs);
char *ft_strschr(char **strs, char *str);
char *ft_getenv(char *var, char **env);

///---------------------- TYPE CONVERSION -----------------------

int ft_atoi(const char *nptr);
long ft_atol(const char *nptr);
int ft_strtoi(const char *str, int *dest);
int ft_strtof(char *str, float *dest, char **ptr);
int ft_strtod(char *str, double *dest, char **ptr);
int ft_strtoul_base(const char *str, unsigned long *dest, const char **ptr,
                    const char *base);
char *ft_itoa(int n);
char *ft_uitoa(unsigned int n);
char *ft_ltoa(long n);
char *ft_ultoa(unsigned long n);
char *ft_ultoa_base(unsigned long n, char *base);
size_t ft_putunbr_buffer(unsigned long nbr, char *buffer, size_t size);
size_t ft_putnbr_buffer(long nbr, char *buffer, size_t size);
size_t ft_putunbr_base_buffer(unsigned long nbr, char *buffer, size_t size,
                              const char *base);

///------------------------ ITERATION ---------------------------

char *ft_strmapi(char const *s, char (*f)(unsigned int, char));
void ft_striteri(char *s, void (*f)(unsigned int, char *));

///------------------------ FD I/O ----------------------------

void ft_putchar_fd(char c, int fd);
void ft_putstr_fd(char *s, int fd);
void ft_putendl_fd(char *s, int fd);
void ft_putnbr_fd(int n, int fd);

/* ---------------------------------- ERROR --------------------------------- */

void *alloc_error(void);
void *null_error(char *msg);

/* ---------------------------------- PRINT --------------------------------- */

void ft_print_strs(char **strs);

/*--------------------------------------------------------------
---------------------------- LIST ------------------------------
-----------------------------------------------------------------*/

typedef struct s_list {
    void *content;
    struct s_list *next;
} t_list;

///----------------------- EDITION ----------------------------

t_list *ft_lstnew(void *content);
void ft_lstadd_front(t_list **list, t_list *new);
void ft_lstadd_back(t_list **list, t_list *new);
void ft_lstinsert(t_list *node_before, t_list *node);
void ft_lstdelone(t_list *list, void (*del)(void *));
void ft_lstdelif(t_list **lst, int (*f)(void *), void (*del)(void *));
void ft_lstclear(t_list **list, void (*del)(void *));
void ft_lstiter(t_list *list, void (*f)(void *));
t_list *ft_lstmap(t_list *lst, void *(*f)(void *), void (*del)(void *));
t_list *ft_lstmerge(t_list *node, t_list **from);
void ft_lstinsert_comp(t_list **list, t_list *node, int (*comp)(void *, void *),
                       bool reverse);
void ft_lstpop_front(t_list **list, void (*del)(void *));

///----------------------- READ ------------------------------

int ft_lstsize(t_list *lst);
t_list *ft_lstlast(t_list *lst);
void ft_lstprint(t_list *pt, void (*disp)(void *));
t_list *ft_lstat(t_list *list, const unsigned int index);

/* ------------------------------- STRING LIST ------------------------------ */

void ft_lst_str_print(t_list *lst);
int ft_lst_str_append(t_list **lst, char *str);
char **ft_lsttostrs(t_list *list);
t_list *ft_strstolst(char **strs);

/*--------------------------------------------------------------
--------------------------- VECTORS -----------------------------
-----------------------------------------------------------------*/

typedef void t_vector;
typedef struct {
    size_t len;
    size_t capacity;
    size_t type_size;
} t_vector_header;

typedef struct {
    t_vector_header header;
    t_vector *data;
} t_vector_struct;

t_vector *ft_vector_create(size_t type_size, size_t initial_capacity);
int ft_vector_reserve(t_vector **vector_addr, size_t nbr_el);
int ft_vector_pop(t_vector **vector_addr);
int ft_vector_pop_range(t_vector **vector_addr, size_t n);
int ft_vector_erase(t_vector **vector_addr, size_t pos);
int ft_vector_erase_range(t_vector **vector_addr, size_t pos, size_t n);
int ft_vector_push(t_vector **vector_addr, const void *data);
int ft_vector_push_range(t_vector **vector_addr, const void *data, size_t n);
int ft_vector_insert(t_vector **vector_addr, size_t pos, const void *data);
int ft_vector_insert_range(t_vector **vector_addr, size_t pos, const void *data,
                           size_t n);
int ft_vector_resize(t_vector **vector_addr, size_t size);
void ft_vector_iter(t_vector *vector, void (*f)(void *));

void ft_vector_free(t_vector **vector_addr);
size_t ft_vector_size(const t_vector *vector);
void ft_dump_vector(t_vector *vector, bool print_capacity);

/*--------------------------------------------------------------
--------------------------- BST --------------------------------
-----------------------------------------------------------------*/

/// @brief Simple binary search tree implementation, reject any doubloon.
typedef struct s_sbtree {
    void *data;
    struct s_sbtree *right;
    struct s_sbtree *left;
} t_sbtree;

int ft_sbtree_insert(t_sbtree **parent, const void *data,
                     int (*cmp)(const void *, const void *));
int ft_sbtree_remove(t_sbtree **root, const void *data,
                     int (*cmp)(const void *, const void *),
                     void (*free_fun)(void *));
void ft_sbtree_clear(t_sbtree *root, void (*free_func)(void *));

size_t ft_sbtree_size(const t_sbtree *root);
size_t ft_sbtree_height(const t_sbtree *root, int height);
int ft_sbtree_shortest(const t_sbtree *root);
// Following functions have an equivalent suffixed by _node returning the node
// instead of the data
const void *ft_sbtree_find(const t_sbtree *root, const void *data,
                           int (*cmp)(const void *, const void *));
const void *ft_sbtree_max(const t_sbtree *root);
const void *ft_sbtree_min(const t_sbtree *root);
const void *ft_sbtree_lower_bound(const t_sbtree *root, const void *data,
                                  int (*cmp)(const void *, const void *));
const void *ft_sbtree_upper_bound(const t_sbtree *root, const void *data,
                                  int (*cmp)(const void *, const void *));
// const t_sbtree*	ft_sbtree_find_node(const t_sbtree* root, const void* data,
// int (*cmp)(const void*, const void*)); const t_sbtree*
// ft_sbtree_max_node(const t_sbtree* root); const t_sbtree*
// ft_sbtree_min_node(const t_sbtree* root); const t_sbtree*
// ft_sbtree_lower_bound_node(const t_sbtree* root, const void* data, int
// (*cmp)(const void*, const void*)); const t_sbtree*
// ft_sbtree_upper_bound_node(const t_sbtree* root, const void* data, int
// (*cmp)(const void*, const void*));

#define ft_sbtree_print(tree) _ft_sbtree_print(tree, 0, NULL)
#define ft_sbtree_print_fun(tree, fun) _ft_sbtree_print(tree, 0, fun)
void _ft_sbtree_print(const t_sbtree *tree, int level,
                      void (*print_func)(const void *));

/*--------------------------------------------------------------
---------------------- SORTING -----------------------------
-----------------------------------------------------------------*/

void _ft_insertion_sort(void *range, size_t n, size_t el_size,
                        int (*cmp)(void *a, void *b), bool rev);
#define ft_insertion_sort(range, n, cmp_func, rev)                             \
    (_ft_insertion_sort(range, n, sizeof(*range), cmp_func, rev))

int _ft_merge_sort(void *range, size_t len, size_t el_size,
                   int (*cmp)(void *a, void *b), bool rev);
#define ft_merge_sort(range, n, cmp_func, rev)                                 \
    (_ft_merge_sort(range, n, sizeof(*range), cmp_func, rev))

/*--------------------------------------------------------------
---------------------- GET_NEXT_LINE -----------------------------
-----------------------------------------------------------------*/

char *ft_gnl(int fd);

/*--------------------------------------------------------------
---------------------------- PRINTF -----------------------------
-----------------------------------------------------------------*/

size_t ft_sprintf(char *buffer, size_t size, const char *format, ...);
void ft_sdprintf(int fd, const char *format, ...);
int ft_printf(const char *str, ...);
int ft_dprintf(int fd, const char *str, ...);

// Error handling
void *null_error(char *msg);
void *format_error(int error, char *parsing);
void *alloc_error(void);
int arg_index_error(int error, int index);
bool flag_error(char flag);

///* ```# alternate form``` Value is converted to alternate form.
///* For x or X : a non zero result has the string 0x placed before
///*
///* ```0 zero_padding``` The value is padded on the left with zero
///* instead of blank. Works for ```d, i, u, x, X```. A minimum width
///* must be defined. Will be ignored if it comes with a precision flag
///*
///* ```- left_justify``` The value is left adjusted on the given width.
///* Overrides a 0 if both given.
///*
///* ```' ' sign_blank``` A blank is left before a positive number.
///* Doesn't affect negative numbers.
///*
///* ```+ force_sign``` A sign is always placed before a signed number.
///* Overrides ```' '``` if both given. Expand field width if necessary.
///*
///* ```. precision``` Defines if a precision was given.
typedef struct s_flags {
    bool alternate_form;
    bool zero_padding;
    bool left_justify;
    bool sign_blank;
    bool force_sign;
    bool precision;
} t_flags;

///* ### Flags
///*
///* Boolean list of all flags. All flags are set to false by default.
///*
///* ### Width
///*
///* Define a minimum field width. Default padding is right unless
///* ```-``` flag has been given.
///* Can be given as a decimal digit or as * to use the value specified
///* in a given argument.
///*
///* ### Precision
///*
///* Defines the minimum number of digit to appear for ```d, i, u, x, X```
///* conversion or the maximum number of character to be printed for ```s```
///*  conversion. Overrides given field width if bigger. A 0 precision will
///* only print non-zero numbers and won't print any character when applied to a
///* string conversion.
///*
///* ### Type
///*
///* ```c``` print a char
///* ```s``` print a string
///* ```p``` print hexadecimal address
///* ```d``` print decimal number
///* ```i``` print integer in base 10
///* ```u``` print unsigned decimal
///* ```x``` print a number in hexadecimal using lowercase char
///* ```X``` print a number in hexadecimal using uppercase char
///* ```%``` print '%' sign
///* ```ld``` long int
///* ```ls``` long signed int
///* ```lu``` long unsigned int
///*
///* ### Value
///*
///* Address of the value to print. Type is specified in conversion member.
///* NULL if value is not assigned yet (case of %).
typedef struct s_field {
    t_flags flags;
    size_t width;
    int precision;
    char type;   // 0 => ld, 1 => lu, 2 => lx, 3 => lX
    void *value; // Should be able to store all type
} t_field;

// #define FT_PRINTF_TYPE

// Structure util

t_list *new_field_node(void);
void init_field(t_field *field);
void free_field(void *field);

// Input parsing

t_list *build_fields(char *str, va_list *va_args);
char *get_next_field(char *str, t_list **fields, t_list **args_req,
                     int *arg_index);
char *parse_field(char *str, t_field *field, t_list **args_req, int *arg_index);

// Field parsing

char *parse_arg_index(char *str, int *arg_index, int *given_index, bool begin);
char *parse_flags(char *str, t_field *field);
char *parse_width(char *str, t_field *field, t_list **args_req, int *arg_index);
char *parse_precision(char *str, t_field *field, t_list **args_req,
                      int *arg_index);
char *parse_conversion_type(char *str, t_field *field);

typedef struct s_arg_req {
    size_t index;
    void *dest;
    char type;
} t_arg_req;

// Struct util

t_list *new_argument_node(void);
t_list *insert_arg_req(t_list **args_req, t_list *arg_node);

// Args retrieving

t_list *register_arg_request(t_list **args_req, void *dest, size_t index,
                             char type);
int retrieve_arguments(t_list *args_req, va_list *va_args);

// Check

bool check_index_format(int new_format, int given_index, char *parsing);
bool check_type_conflict(t_arg_req *node1, t_arg_req *node2);
bool check_flag_conflict(t_field *field);
bool check_fields(t_list *fields);

// Printing functions

int print_fields(int fd, t_list *fields);
int print_field(int fd, t_field *field);
char *build_str(t_field *field);
char *get_str_value(t_field *field);

// Conversion

char *char_to_str(char c);
char *address_to_str(unsigned long addr);
char *str_to_str(char *str);
char *hexa_to_str(unsigned long nbr, char type);

// Formatting

char *format_str(t_field *field, char *str);
char *format_precision(t_field *field, char *str);
char *format_alt_form(t_field *field, char *str);
char *format_sign(t_field *field, char *str);
char *format_width(t_field *field, char *str);
char *insert_n_char(char *str, int start, int n, char c);

/*--------------------------------------------------------------
---------------------- FT_OPTIONS -----------------------------
-----------------------------------------------------------------*/

// A data structure that will be given to the handler, containing for example
// the list of enable flags
typedef struct s_options t_options;

enum ARG_TYPE { ARG_NONE, ARG_OPTIONNAL, ARG_REQUIRED };

typedef struct s_option_flag {
    char short_id;
    char *long_id;
    enum ARG_TYPE arg;
    int (*handler)(t_options *, char *);
} t_opt_flag;

int ft_options_retrieve(int nbr, char **args, t_options *options,
                        unsigned int *dest_nbr_args);
int ft_options_err_invalid_argument(const char *option, const char *arg,
                                    const char ***valids);
int ft_options_err_ambiguous_argument(const char *option, const char *arg,
                                      const char ***valids);
int ft_options_err_incompatible_options(const char *option1,
                                        const char *option2);

int check_options(t_options *options) __attribute__((weak));

#endif
