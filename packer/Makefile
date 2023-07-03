CFLAGS_COMMON = -Wall -std=gnu99 -I .. -I../cyclone_cipher -I../cyclone_cipher/common
# CFLAGS_COMMON = -Wall -Werror -std=gnu99 -I ..
CFLAGS = $(CFLAGS_COMMON)
LDFLAGS = -Lbddisasm/bin/x64/Release -static
LIB = -L../cyclone_cipher -lcrypto

SRCS = $(wildcard *.c ../common/*.c ../loader/malloc.c ../loader/syscalls.c ../loader/debug.c ../loader/string.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
BIN_NAME = kiteshield

.PHONY: all debug debug-antidebug output-dirs clean

debug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT -DNO_ANTIDEBUG
# 开启反调试功能的debug
debug-antidebug: CFLAGS = $(CFLAGS_COMMON) -g -DDEBUG_OUTPUT

all: output-dirs $(OBJS)
	$(CC) $(OBJS) $(LIB) -o $(BIN_NAME) $(LDFLAGS)

debug: all
debug-antidebug: all

output-dirs:
	mkdir -p obj

obj/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/malloc.o: ../loader/malloc.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/syscalls.o: ../loader/syscalls.c
	$(CC) $(CFLAGS) -c ../loader/syscalls.c -o obj/syscalls.o

obj/debug.o: ../loader/debug.c
	$(CC) $(CFLAGS) -c ../loader/debug.c -o obj/debug.o

obj/string.o: ../loader/string.c
	$(CC) $(CFLAGS) -c ../loader/string.c -o obj/string.o

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
