main:
	gcc main.c -static -e main -I. -I./cyclone_cipher -I./cyclone_cipher/common -L./cyclone_cipher -lcrypto -std=gnu99 -fno-pie -nostdlib -nostartfiles -nodefaultlibs -fno-builtin -g -o main
clean:
	rm -rf main