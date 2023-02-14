#ifndef _DES_H_
#define _DES_H_
#include "loader/include/malloc.h"
#include "loader/include/string.h"

#define ENCRYPTION_MODE 1
#define DECRYPTION_MODE 0
#define DES_KEY_SIZE 8

typedef unsigned char des_key[DES_KEY_SIZE];

typedef struct {
	unsigned char k[8];
	unsigned char c[4];
	unsigned char d[4];
} key_set;

void generate_key(unsigned char* key);
void generate_sub_keys(unsigned char* main_key, key_set* key_sets);
void process_message(unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode);
void des_init(des_key key);
void des_encrypt(unsigned char* in, unsigned char* out, unsigned long * len, des_key key);
void des_decrypt(unsigned char* in, unsigned char* out, unsigned long * len, des_key key);
void print_hex(unsigned char* data, int len);

#endif
