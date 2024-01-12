CFLAGS_COMMON = -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -c -g
CFLAGS = -I. -I.. -I./common -c -w -fno-stack-protector -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -g $(CFLAGS_COMMON)
SRCS = pkc/rsa.c mpiCheckProbablePrime.c os_port_x86.c mpi/mpi.c mac/hmac.c encoding/oid.c cipher/aes.c cipher/des.c cipher/des3.c cipher/rc4.c cipher_modes/ecb.c rng/yarrow.c \
		hash/sha256.c common/cpu_endian.c malloc.c syscalls.c string.c
OBJS = $(SRCS:.c=.o)

.PHONY: clean
	
lib: $(OBJS)
	$(AR) rcs libcrypto.a $^

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJS) main libcrypto.a