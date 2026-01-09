NAME		=	libft.a

CC			=	gcc
CFLAGS		=	-Wall -Wextra -g3 -fPIC

ifeq ($(ARCH_TYPE), 32)
	CFLAGS += -m32 -D__ARCH_TYPE=$(ARCH_TYPE)
else ifeq ($(ARCH_TYPE), 64)
	CFLAGS += -m64 -D__ARCH_TYPE=$(ARCH_TYPE)
else
	CFLAGS += -m64 -D__ARCH_TYPE=64
endif

ifeq ($(VALGRIND),)
	CFLAGS += -fsanitize=address
endif

ifneq ($(OPTI),)
	CFLAGS += -O2
endif

SRCS		=	ft_memset.c ft_bzero.c ft_calloc.c ft_memcpy.c ft_memmove.c \
				ft_memchr.c ft_memcmp.c ft_memswap.c ft_strlen.c ft_strdup.c \
				ft_strlcat.c ft_strlcpy.c ft_strchr.c \
				ft_strrchr.c ft_strnstr.c ft_strcmp.c \
				ft_atoi.c ft_isalpha.c ft_isdigit.c ft_isalnum.c ft_isascii.c ft_isspace.c \
				ft_isprint.c ft_toupper.c ft_tolower.c \
				ft_strmapi.c ft_substr.c ft_strjoin.c ft_strjoin2.c ft_strtrim.c ft_split.c \
				ft_itoa.c ft_striteri.c ft_uitoa.c ft_ultoa.c ft_ultoa_base.c ft_ltoa.c \
				ft_strtoul_base.c \
				ft_putchar_fd.c ft_putstr_fd.c ft_putendl_fd.c ft_putnbr_fd.c \
				ft_putunbr_buffer.c ft_putnbr_buffer.c \
				ft_lstadd_back.c ft_lstadd_front.c ft_lstclear.c ft_lstdelone.c \
				ft_lstiter.c ft_lstlast.c ft_lstmap.c ft_lstnew.c ft_lstsize.c ft_lstinsert.c \
				ft_lstmerge.c ft_lstprint.c ft_lst_str.c ft_lstdelif.c ft_lstinsert_comp.c \
				ft_lstpop_front.c ft_lstat.c \
				ft_printf_args.c ft_printf_field.c	 ft_printf_parse_flags.c \
				ft_printf.c ft_printf_field_util.c ft_printf_parse_index.c \
				ft_printf_format.c	 ft_printf_printing.c \
				ft_printf_check.c ft_printf_format_util.c ft_printf_str_conversion.c \
				ft_printf_error.c ft_gnl.c ft_error.c ft_abs.c ft_imax.c ft_atol.c ft_strtof.c \
				ft_strtod.c ft_dmax.c ft_max.c ft_getenv.c \
				ft_strtoi.c ft_print_strs.c ft_strslen.c ft_strsslen.c ft_free_strss.c \
				ft_strschr.c ft_free_strs.c \
				ft_hexdump.c ft_vector.c ft_sort.c ft_case.c ft_sprintf.c \
				ft_options.c ft_sbtree.c


INCLUDES	=	./

OBJS_FOLDER	=	.objs
OBJS		=	$(addprefix $(OBJS_FOLDER)/,$(SRCS:.c=.o))

.PHONY		=	all clean fclean test re bonus so

all: $(NAME)

test: $(NAME) tests/main.c
	$(CC) $(CFLAGS) -I$(INCLUDES) tests/main.c -L. -lft

a.out: main.c $(NAME)
	$(CC) $(CFLAGS) -I$(INCLUDES) main.c ${NAME}
	@echo "Executable has been successfully created."

$(NAME): $(OBJS)
	@echo "---- COMPILING LIBFT -------"
	ar crs ${NAME} ${OBJS}
	@echo "$(NAME) has been successfully created."


$(OBJS_FOLDER)/%.o: %.c Makefile libft.h
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(INCLUDES) -c -o $@ $<

so: libft.so

libft.so: $(SRCS)
	$(CC) -nostartfiles -fPIC $(CFLAGS) -I$(INCLUDES) $(SRCS)
	gcc -nostartfiles -shared -o libft.so $(OBJS)
	cp libft.so ../libft-unit-tests/libft.so

clean:
	@echo "---------CLEANING LIBFT OBJECT FILES---------"
	rm -rf $(OBJS) libft.so
	rm -rdf $(OBJS_FOLDER)
	@echo "object files have been removed."

fclean: clean
	@echo "-------CLEANING LIB AND EXECUTABLE ---------"
	rm -f $(NAME)
	rm -f a.out
	@echo "$(NAME) and object files have been removed."

re: fclean all
