CFLAGS = -fno-stack-protector -nostdlib -nostartfiles -nodefaultlibs -I./ -DNDEBUG -g
SRCS = zstd.c roundtrip.c malloc.c string.c syscalls.c
SRCS2 = simple.c malloc.c string.c syscalls.c

# test_zstd:
# 	$(CC) $(CFLAGS) $(SRCS) -e main -o $@
.PHONY: clean

test_zstd_decompress:
	$(CC) $(CFLAGS) $(SRCS2) -e main -o $@

clean:
	rm test_zstd_decompress