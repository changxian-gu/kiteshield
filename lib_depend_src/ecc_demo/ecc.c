#include "ecc.h"
#include "rc4.h"
// #include <assert.h>
/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
  return (x << k) | (x >> (32 - k)); 
}

static uint32_t prng_next(void)
{
  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i) 
  {
    (void) prng_next();
  }
}

int ecc_init_keys(uint8_t *pub, uint8_t *pri)
{
    uint8_t puba[ECC_PUB_KEY_SIZE];
    uint8_t prva[ECC_PRV_KEY_SIZE];
    uint8_t pubb[ECC_PUB_KEY_SIZE];
    uint8_t prvb[ECC_PRV_KEY_SIZE];

    int i = 0;
    /* 0. Initialize and seed random number generator */
    static int initialized = 0;
    if (!initialized)
    {
        prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
        initialized = 1;
    }
    /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prva[i] = prng_next();
    }
    if(ecdh_generate_keys(puba, prva)!=1) return -1;

    /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
    for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
    {
        prvb[i] = prng_next();
    }
    assert(ecdh_generate_keys(pubb, prvb));

    for(i = 0; i< ECC_KEYSIZE;i++)
    {
        if(i<ECC_PRV_KEY_SIZE)
        {
            pub[i] = prva[i];
            pri[i] = prvb[i];
        }
        else{
            pub[i] = pubb[i-ECC_PRV_KEY_SIZE];
            pri[i] = puba[i-ECC_PRV_KEY_SIZE];
        }
    }
    return 1;
}

int ecc_encrypt(uint8_t *pubkey,uint8_t *in, uint32_t in_size, uint8_t *out, uint32_t *out_size)
{
    uint8_t common_key[ECC_PUB_KEY_SIZE];
    assert(ecdh_shared_secret(pubkey, pubkey+ECC_PRV_KEY_SIZE, common_key));
    struct rc4_state rc4;
    rc4_init(&rc4,common_key,ECC_PUB_KEY_SIZE);
    int i =0;
    for(i=0; i< in_size;i++)
    {
      unsigned char b = rc4_get_byte(&rc4);
      out[i] = b ^ in[i];
    }
    *out_size = in_size;
    return *out_size;
}
int ecc_decrypt(uint8_t *prvkey,uint8_t *in, uint32_t in_size, uint8_t *out, uint32_t *out_size)
{
    uint8_t common_key[ECC_PUB_KEY_SIZE];
    assert(ecdh_shared_secret(prvkey, prvkey+ECC_PRV_KEY_SIZE, common_key));
    struct rc4_state rc4;
    rc4_init(&rc4,common_key,ECC_PUB_KEY_SIZE);
    int i =0;
    for(i=0; i< in_size;i++)
    {
      unsigned char b = rc4_get_byte(&rc4);
      out[i] = b ^ in[i];
    }
    *out_size = in_size;
    return *out_size;

}
