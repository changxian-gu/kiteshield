CFLAGS_COMMON = -Wall -std=gnu99 -I .. -I../cyclone_cipher -I../cyclone_cipher/common -I../compression/lzma -I../compression/lzo -I../compression/ucl \
				-I../compression/ucl/include -I../compression/ucl/src
# CFLAGS_COMMON = -Wall -Werror -std=gnu99 -I ..
CFLAGS = $(CFLAGS_COMMON)
# 目前zstd算法的外壳支持使用zstd库
LDFLAGS = -Lbddisasm/bin/x64/Release -static -L../compression/zstd/ -lzstd -L../compression/ucl/ -lucl
LIB = -L../cyclone_cipher -lcrypto -lecc

SRCS = $(wildcard *.c ../common/*.c ../loader/debug.c ../compression/lzma/*.c ../compression/lzo/*.c)

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

obj/%.o: ../loader/%.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../compression/lzma/%.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../compression/lzo/%.c
	$(CC) $(CFLAGS) -c $< -o $@

obj/%.o: ../compression/ucl/src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BIN_NAME)
	rm -rf obj/
