SRCS = $(wildcard src/*.c)
OBJS = $(addprefix ./obj/, $(notdir $(SRCS:.c=.o)))
CFLAGS = -I. -I./include -I./src -nodefaultlibs -nostartfiles -fno-stack-protector -g

.PHONY:
	clean output-dir

all: output-dir main

main: $(OBJS)
	$(CC) $(CFLAGS) -e main $^ -o $@

output-dir:
	mkdir -p obj

obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

lib: $(OBJS)
	ar rcs libucl.a $(OBJS)

obj/%.o: examples/simple.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf ./obj main
