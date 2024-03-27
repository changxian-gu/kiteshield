#ifndef ECC_H
#define ECC_H
#include "ecdh.h"

#define assert(condition) if (!(condition)) { *((int*)0) = 0; }

#define ECC_KEYSIZE ECC_PUB_KEY_SIZE+ECC_PRV_KEY_SIZE
int ecc_init_keys(uint8_t *pub, uint8_t *pri);

int ecc_encrypt(uint8_t *pubkey,uint8_t *in, uint32_t in_size,uint8_t *out, uint32_t *out_size);
int ecc_decrypt(uint8_t *prvkey, uint8_t *in, uint32_t in_size,uint8_t *out, uint32_t *out_size);


#endif