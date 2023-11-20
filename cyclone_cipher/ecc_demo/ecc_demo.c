#include "ecc.h"
#include <stdio.h>

void sys_exit(int status)
{
  int ret = 0;

  asm volatile(
      "mov x0, %[val0]\n"
      "stp x29, x30, [sp, -16]!\n"
      "mov x8, #93 \n"
      "svc #0 \n"
      "ldp x29, x30, [sp], 16\n"
      "mov %[result], x0"
      :[result]"=r"(ret)
      :[val0]"r"(status)
  );

  /* Required so GCC accepts __attribute__((noreturn)) on this function */
  while(1) {}
}
int main()
{
    uint8_t plaint[256];
    uint8_t enc_buf[256];
    uint8_t dec_buf[256];
    int i = 0;
    for(i = 0;i<256;i++)
    {
        plaint[i] = i%256;
    }
    uint8_t pub_key[ECC_KEYSIZE];
    uint8_t prv_key[ECC_KEYSIZE];
    ecc_init_keys(pub_key,prv_key);

    uint32_t out_size;
    ecc_encrypt(pub_key,plaint,256,enc_buf,&out_size);

    ecc_decrypt(prv_key, enc_buf,256,dec_buf,&out_size);
    int equal = 1;
    for(i=0; i<256;i++)
    {
        if(plaint[i] != dec_buf[i])
        {
            equal =0;
            break;
        }
    }
    if(equal == 0)
    {
        // printf("fail\n");
        sys_exit(1);
    }else{
        // printf("success\n");
        sys_exit(0);
    }
}