#include <libft.h>
#include <stdarg.h>

static size_t	put_str_buffer(char* buffer, size_t buffer_size, char* str) {
	size_t	s_len;

	if (str == NULL)
		str = "(null)";
	s_len = ft_strlen(str);
	ft_strlcpy(buffer, str, buffer_size);
	return (s_len + 1 > buffer_size ? buffer_size - 1 : s_len);
}

static size_t	put_ptr_str(char* buffer, size_t size, void* ptr) {
	size_t	nwrite;
	if (ptr == NULL)
		return (put_str_buffer(buffer, size, "(nil)"));
	nwrite = put_str_buffer(buffer, size, "0x");
	if (nwrite != 2)
		return (nwrite);
	nwrite += ft_putunbr_base_buffer((size_t)ptr, buffer + 2, size - 2, "0123456789abcdef");
	return (nwrite);
}

static size_t	parse_format(char* buffer, size_t size, const char* format, va_list args) {
	size_t	len = 0;
	size_t	nwrite;

	while (*format && len + 1 < size) {
		if (*format == '%')
		{
			switch (*(format + 1)) {
				case '%':
					buffer[len] = '%';
					len++;
					format += 2;
					break;
				
				case 'c':
					buffer[len] = (char)va_arg(args, int);
					len++;
					format += 2;
					break;

				case 'd':
					nwrite = ft_putnbr_buffer(va_arg(args, int), buffer + len, size - len);
					len += nwrite;
					format += 2;
					break;

				case 'i':
					nwrite = ft_putnbr_buffer(va_arg(args, int), buffer + len, size - len);
					len += nwrite;
					format += 2;
					break;

				case 'u':
					nwrite = ft_putunbr_buffer(va_arg(args, unsigned int), buffer + len, size - len);
					len += nwrite;
					format += 2;
					break;

				case 's':
					nwrite = put_str_buffer(buffer + len, size - len, va_arg(args, char*));
					len += nwrite;
					format += 2;
					break;

				case 'p':
					nwrite = put_ptr_str(buffer + len, size - len, va_arg(args, void*));
					len += nwrite;
					format += 2;
					break;

				case 'x':
					nwrite = ft_putunbr_base_buffer(va_arg(args, unsigned int), buffer + len, size - len, "0123456789abcdef");
					len += nwrite;
					format += 2;
					break;

				case 'X':
					nwrite = ft_putunbr_base_buffer(va_arg(args, unsigned int), buffer + len, size - len, "0123456789ABCDEF");
					len += nwrite;
					format += 2;
					break;

				case 'l':
					switch (*(format + 2))
					{
						case 'd':
							nwrite = ft_putnbr_buffer(va_arg(args, long int), buffer + len, size - len);
							len += nwrite;
							format += 3;
							break;

						case 'u':
							nwrite = ft_putunbr_buffer(va_arg(args, long unsigned int), buffer + len, size - len);
							len += nwrite;
							format += 3;
							break;

						case 'x':
							nwrite = ft_putunbr_base_buffer(va_arg(args, long unsigned int), buffer + len, size - len, "0123456789abcdef");
							len += nwrite;
							format += 3;
							break;

						case 'X':
							nwrite = ft_putunbr_base_buffer(va_arg(args, long unsigned int), buffer + len, size - len, "0123456789ABCDEF");
							len += nwrite;
							format += 3;
							break;
						
						default:
							nwrite = put_str_buffer(buffer + len, size - len, "%l");
							len += nwrite;
							format += 2;
							break;
					}
					break;

				default:
					buffer[len] = '%';
					len++;
					format += 1;
					break;
			}
		} else {
			buffer[len] = *format;
			len++;
			format++;
		}
	}
	if (*format) {
		ft_strlcpy(buffer + len, format, size - len);
		return (size - 1);
	}
	buffer[len] = '\0';
	return (len);
}




/// @brief Static printf implementation to format string inside buffers without
/// allocation. Doesn't raise any error. Null terminate the buffer at the end.
/// Handles %d, %i, %u, %x, %X, %s, %c, %p, %ld, %lu, %li, %lx, %lX, %%
/// @warning Flag, width and precision not implemented
/// @param buffer buffer to write into
/// @param size of the buffer 
/// @param format
/// @return Number of characters written into the buffer
size_t	ft_sprintf(char* buffer, size_t size, const char* format, ...) {
	va_list	args;
	size_t	nwrite;

	if (buffer == NULL || format == NULL || size == 0)
		return (0);
	va_start(args, format);
	nwrite = parse_format(buffer, size, format, args);
	va_end(args);
	buffer[nwrite] = '\0';
	return (nwrite);
}

/// @brief Static implementation of dprintf without any allocation.
/// Handles %d, %i, %u, %x, %X, %s, %c, %p, %ld, %lu, %li, %lx, %lX, %%
/// @note Size of static buffer depends of ```BUFFER_SIZE``` define.
/// @param fd 
/// @param format 
void	ft_sdprintf(int fd, const char* format, ...) {
	char	buffer[BUFFER_SIZE];
	size_t	nwrite;
	va_list	args;

	if (format == NULL || fd < 0)
		return;
	va_start(args, format);
	nwrite = parse_format(&buffer[0], BUFFER_SIZE, format, args);
	va_end(args);
	buffer[nwrite] = '\0';
	write(fd, buffer, nwrite);
}

