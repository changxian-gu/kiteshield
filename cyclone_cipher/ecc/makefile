# 指定编译器
CC = gcc

# 指定编译选项
CFLAGS = -Wall -O2 -std=gnu99 -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -fPIE -I./

# 指定目标文件
TARGET = ecc_demo

# 指定源文件
# SOURCES = ecc.c ecdh.c rc4.c ecc_demo.c
SOURCES = ecc.c ecdh.c rc4.c

# 生成目标文件名
OBJECTS = $(SOURCES:.c=.o)

# 默认目标
all: $(TARGET)

# 生成可执行文件
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -e main -o $(TARGET) $(OBJECTS)

main: ecc_demo.o $(OBJECTS)
	$(CC) $(CFLAGS) ecc_demo.o -L../ -lecc -e main -o main

lib: $(OBJECTS)
	ar rcs ../libecc.a $^
# 生成目标文件
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# 清除中间文件和可执行文件
clean:
	rm -f $(OBJECTS) $(TARGET)
