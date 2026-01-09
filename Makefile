NAME		=	ft_nmap

INCLUDES	=	includes/
SRCS_FOLDER	=	srcs/
OBJS_FOLDER	=	.objs/

SRCS_FILES	=	main.c  parse_args.c error.c socket.c 

OBJS		=	$(addprefix $(OBJS_FOLDER),$(SRCS_FILES:.c=.o))
SRCS		=	$(addprefix $(SRCS_FOLDER),$(SRCS_FILES))
DEPS		=	$(addprefix $(OBJS_FOLDER), $(SRCS_FILES:.cpp=.d))

LIBFT		=	libft/libft.a

CC			=	gcc
CFLAGS		=	-fsanitize=address -Wall -Wextra -Werror -g3 -MMD -I$(INCLUDES)

.PHONY		=	all clean fclean re bonus

-include	$(wildcard *.d)

all: $(NAME)

$(NAME): $(LIBFT) $(OBJS)
	@echo "\n-----COMPILING $(NAME)-------\n"
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -Llibft/ -lft -lm
	@echo "Executable has been successfully created."


$(OBJS_FOLDER)%.o: $(SRCS_FOLDER)%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(INCLUDES)libft.h: libft/libft.h
	@echo "------ UPDATING LIBFT HEADER -------\n"
	cp libft/libft.h includes/libft.h

libft/libft.h:
	$(MAKE) update-submodules

$(LIBFT): $(INCLUDES)libft.h
	@echo "\n-------COMPILING LIBFT--------------\n"
	make -C libft/
	make clean -C libft/
	@echo "\n\n"

update-submodules:
	git submodule update --init --recursive
# 	git submodule foreach git pull origin master

docker-limit:
	docker build -t debian_c .
	docker run --rm -it \
		--name debian_limit \
		--cap-add=NET_ADMIN \
		debian_c \
		bash -c "tc qdisc add dev eth0 root tbf rate 50kbps burst 1600 limit 3000 && tc qdisc add dev eth0 root netem loss 100% && exec bash"


docker:
	docker build -t debian_c . && docker run --network=host --cap-add=NET_RAW -it debian_c

tcpdump:
	docker run --rm --net container:$$(docker ps -q) --cap-add NET_RAW nicolaka/netshoot tcpdump -x -i eth0 icmp

clean:
	@echo "\n-------------CLEAN--------------\n"
	make clean -C libft/
	rm -rf $(OBJS_FOLDER)
	@echo "object files have been removed."

fclean: clean
	@echo "\n-------------FORCE CLEAN--------------\n"
	make fclean -C libft/
	rm -rf $(NAME)
	@echo "$(NAME) and object files have been removed."

re: fclean all

