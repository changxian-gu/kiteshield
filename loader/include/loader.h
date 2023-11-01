#ifndef KITESHIELD_LOADER_H
#define KITESHIELD_LOADER_H

#endif //KITESHIELD_LOADER_H

extern struct rc4_key obfuscated_key;
extern unsigned char serial_key[16];

void reverse_shuffle(unsigned char *arr, int n, unsigned char swap_infos[]);