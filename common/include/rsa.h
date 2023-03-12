#ifndef _RSA_H_
#define _RSA_H_
#include "bn.h"
#include "../../loader/include/string.h"

void print_bytes(unsigned char *str, int len);
void my_reverse(void *src, unsigned long start, unsigned long end);
// bignum底层存储使用的uint32小端序存储
void rsa_memcpy(void *dest, void *src, unsigned long len);
typedef struct rsa_key
{
  char n[128];
  char d[128];
  char e[128];
}__attribute__((packed)) rsa_key;
/* O(log n) */
void pow_mod_faster(struct bn *a, struct bn *b, struct bn *n, struct bn *res);
void rsa_encrypt(unsigned char *msg, unsigned char *ciphertext, unsigned long len, rsa_key *key);
void rsa_decrypt(unsigned char *ciphertext, unsigned char *msg, unsigned long len, rsa_key *key);
void rsa_init(rsa_key* key);

#endif