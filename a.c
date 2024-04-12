#include <sys/ptrace.h>
#include <elf.h>
#include <stdio.h>

void printBytes(const char *msg, unsigned long len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", (unsigned char)(msg[i]));
    }
    printf("\n");
}

int main() {
    long word = (~0);
    printBytes(&word, 8);
     word = (~0L) << 32;
    printBytes(&word, 8);
     word = (~0UL) << 32;
    printBytes(&word, 8);
    return 0;
}
