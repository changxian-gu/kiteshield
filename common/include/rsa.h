// #include "../loader/include/string.h"
#include "./include/bn.h"
#include <string.h>

void print_bytes(unsigned char *str, int len);
void my_reverse(void *src, unsigned long start, unsigned long end);
// bignum底层存储使用的uint32 小端序存储
void rsa_memcpy(void *dest, void *src, unsigned long len);
typedef struct rsa_key
{
  char n[128];
  char d[128];
  char e[128];
} rsa_key;
/* O(log n) */
void pow_mod_faster(struct bn *a, struct bn *b, struct bn *n, struct bn *res);
void rsa_encrypt(unsigned char *msg, unsigned long len, rsa_key *key, char *ciphertext);
void rsa_decrypt(char *ciphertext, unsigned long len, rsa_key *key, char *msg);
int rsa_init(rsa_key* key);