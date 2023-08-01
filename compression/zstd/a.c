#include <stdio.h>     // printf
#include <stdlib.h>    // free
#include <string.h>    // strlen, strcat, memset
#include <stddef.h>
#include <stdint.h>
#include <zstd.h>      // presumes zstd library is installed

void print_bytes(uint8_t* buff, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", buff[i]);
    }
    printf("\n");
}

int main() {
    char* in = "0123456789abcdef";
    int in_len = 16;
    print_bytes(in, in_len);

    int out_len = ZSTD_compressBound(in_len);
    char* out = malloc(out_len);
    out_len = ZSTD_compress(out, out_len, in, in_len, 1);
    print_bytes(out, out_len);
    
    uint8_t decompressed_blob[200];
    int decompressed_size = 200;
    decompressed_size = ZSTD_decompress(decompressed_blob, decompressed_size, out, out_len);
    print_bytes(decompressed_blob, decompressed_size);
    return 0;
}
