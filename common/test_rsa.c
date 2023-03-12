// // #include "../loader/include/string.h"
// #include "include/bn.h"
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// void print_bytes(unsigned char *buf, int len) {
//   for (int i = 0; i < len; i++) {
//     printf("%02x", buf[i]);
//   }
//   printf("\n");
// }


// typedef struct rsa_key
// {
//   char n[128];
//   char d[128];
//   char e[128];
// }__attribute__((packed)) rsa_key;

// void my_reverse(void *src, unsigned long start, unsigned long end)
// {
//   unsigned char *p = (unsigned char *)src;
//   unsigned long i = start, j = end - 1;
//   while (i < j)
//   {
//     unsigned char tmp = *(p + i);
//     *(p + i) = *(p + j);
//     *(p + j) = tmp;
//     i++;
//     j--;
//   }
// }

// // bignum 底层使用的小端序存储
// void rsa_memcpy(void *dest, void *src, unsigned long len)
// {
//   unsigned char* p_src = (unsigned char*)src;
//   unsigned char* p_dest = (unsigned char*)dest;
//   unsigned long i = 0;
//   while (i < len) {
//     p_dest[i] = p_src[len - 1 - i];
//     i++;
//   }
// }

// /* O(log n) */
// void pow_mod_faster(struct bn *a, struct bn *b, struct bn *n, struct bn *res)
// {
//   bignum_from_int(res, 1); /* r = 1 */

//   struct bn tmpa;
//   struct bn tmpb;
//   struct bn tmp;
//   bignum_init(&tmp);
//   bignum_assign(&tmpa, a);
//   bignum_assign(&tmpb, b);

//   while (1)
//   {
//     if (tmpb.array[0] & 1) /* if (b % 2) */
//     {
//       bignum_mul(res, &tmpa, &tmp); /*   r = r * a % m */
//       bignum_mod(&tmp, n, res);
//     }
//     bignum_rshift(&tmpb, &tmp, 1); /* b /= 2 */
//     bignum_assign(&tmpb, &tmp);

//     if (bignum_is_zero(&tmpb))
//       break;

//     bignum_mul(&tmpa, &tmpa, &tmp);
//     bignum_mod(&tmp, n, &tmpa);
//   }
// }
// void rsa_encrypt(unsigned char *msg, unsigned char *ciphertext, unsigned long len, rsa_key *key)
// {
//   int bytes_w = 64;
//   int count_64 = len / bytes_w;
//   printf("the count is %d\n", count_64);
//   bignum bn_msg;
//   bignum bn_n, bn_e, bn_c;
//   bignum_init(&bn_n);
//   bignum_init(&bn_e);
//   rsa_memcpy(bn_n.array, key->n, bytes_w);
//   rsa_memcpy(bn_e.array, key->e, 3);
//   int idx = 0;
//   while (idx < count_64) {
//     bignum_init(&bn_msg);
//     bignum_init(&bn_c);
//     rsa_memcpy(bn_msg.array, msg + idx * bytes_w, bytes_w);
//     pow_mod_faster(&bn_msg, &bn_e, &bn_n, &bn_c);
//     rsa_memcpy(ciphertext + idx * bytes_w, bn_c.array, bytes_w);
//     idx++;
//   }


//   // tmp
//   // bignum_init(&bn_msg);
//   // bignum_init(&bn_c);
//   // rsa_memcpy(bn_msg.array, msg, len);
//   // char print_buf[8192];
//   // bignum_to_string(&bn_msg, print_buf, 8192);
//   // printf("the msg is %s\n", print_buf);
//   // pow_mod_faster(&bn_msg, &bn_e, &bn_n, &bn_c);
//   // bignum_to_string(&bn_e, print_buf, 8192);
//   // printf("the e is %s\n", print_buf);
//   // bignum_to_string(&bn_n, print_buf, 8192);
//   // printf("the n is %s\n", print_buf);
//   // bignum_to_string(&bn_c, print_buf, 8192);
//   // printf("the c is %s\n", print_buf);
//   // rsa_memcpy(ciphertext, bn_c.array, bytes_w);
// }

// void rsa_decrypt(unsigned char *ciphertext, unsigned char *msg, unsigned long len, rsa_key *key)
// {
//   int idx = 0;
//   int bytes_w = 64;
//   int count_64 = len / bytes_w;
//   bignum bn_c;
//   bignum bn_m;
//   bignum bn_n, bn_d;
//   bignum_init(&bn_n);
//   bignum_init(&bn_d);
//   rsa_memcpy(bn_n.array, key->n, bytes_w);
//   rsa_memcpy(bn_d.array, key->d, bytes_w);
//   while (idx < count_64) {
//     bignum_init(&bn_c);
//     bignum_init(&bn_m);
//     rsa_memcpy(bn_c.array, ciphertext + idx * bytes_w, bytes_w);
//     pow_mod_faster(&bn_c, &bn_d, &bn_n, &bn_m);
//     rsa_memcpy(msg + idx * bytes_w, bn_m.array, bytes_w);
//     idx++;
//   }

//   //tmp
//   // bignum_init(&bn_c);
//   // bignum_init(&bn_m);
//   // rsa_memcpy(bn_c.array, ciphertext, len);

//   // char print_buf[8192];
//   // bignum_to_string(&bn_c, print_buf, 8192);
//   // printf("the cipher is %s\n", print_buf);

//   // pow_mod_faster(&bn_c, &bn_d, &bn_n, &bn_m);

//   // bignum_to_string(&bn_d, print_buf, 8192);
//   // printf("the d is %s\n", print_buf);
//   // bignum_to_string(&bn_n, print_buf, 8192);
//   // printf("the n is %s\n", print_buf);
//   // bignum_to_string(&bn_m, print_buf, 8192);
//   // printf("the m is %s\n", print_buf);

//   // rsa_memcpy(msg, bn_m.array, len);

// }

// void rsa_init(rsa_key* key)
// {
//   memset(key->n, 0, 128);
//   memset(key->d, 0, 128);
//   memset(key->e, 0, 128);

//   char nstr[] = {0x05, 0xea, 0xab, 0x23, 0x3b, 0x13, 0x71, 0x98, 0xc9, 0xf6, 0x8a, 0x50, 0xd9,
//    0x92, 0x84, 0x14, 0x7c, 0x56, 0x42, 0x6e, 0x71, 0xf3, 0x5e, 0xca, 0xa6, 0xa5, 0x28, 0xde,
//     0x99, 0x07, 0x90, 0x85, 0xad, 0x2b, 0x19, 0x5f, 0x12, 0x74, 0x8b, 0xcd, 0x7c, 0x43, 0xf3,
//      0x08, 0x26, 0xc7, 0x5b, 0xe4, 0x16, 0x97, 0xff, 0x9d, 0x60, 0x95, 0x03, 0x1d, 0x0d, 0xbe,
//       0xbe, 0x21, 0x95, 0x36, 0xf6, 0x39};
//   char estr[] = {0x01, 0x00, 0x01};
//   char dstr[] = {0x03, 0xee, 0x30, 0x61, 0xe7, 0x0c, 0xb3, 0x99, 0xdc, 0x10, 0x7b,
//    0x31, 0xda, 0x57, 0x0a, 0x86, 0xd1, 0x52, 0x3c, 0x2f, 0x42, 0x63, 0x79, 0xc5, 0x05, 0x8f,
//     0x11, 0xe7, 0x4d, 0xa1, 0x48, 0xd0, 0x2d, 0xd4, 0x12, 0x4b, 0x85, 0xfa, 0xdc, 0x7d, 0x9a,
//      0x21, 0xf0, 0xbe, 0x89, 0x17, 0x2f, 0xe9, 0x8f, 0xf8, 0x69, 0xf5, 0x72, 0xb2, 0xc4, 0x7b, 
//      0x00, 0xcf, 0x43, 0x46, 0x5b, 0x8f, 0x09, 0x01};
//   memcpy(key->n, nstr, 64);
//   memcpy(key->e, estr, 3);
//   memcpy(key->d, dstr, 64);
// }

// // int test_rsa(rsa_key* key)
// // {
// //   char msg[] = {0x05, 0x04, 0x03, 0x02, 0x01};
// //   char nstr[] = {0x1e, 0xb0, 0x51, 0x22, 0x5d, 0x03, 0x21, 0x7a, 0x11, 0x32, 0x31, 0xa1, 0x72, 0xbd, 0x04, 0x93,
// //                  0x70, 0x65, 0x66, 0x2e, 0x2c, 0xe1, 0x76, 0x8b, 0xc1, 0x19, 0xde, 0xbe, 0x4a, 0xfd, 0x5d, 0xf4, 0x8e, 0x71,
// //                  0xa1, 0x05, 0x93, 0xa7, 0xce, 0x3a, 0xae, 0x70, 0x7b, 0x26, 0x85, 0xb2, 0x52, 0xe8, 0xe3, 0x58, 0xad, 0x5f,
// //                  0x3e, 0x72, 0x9e, 0x1b, 0x6b, 0xea, 0xdd, 0x98, 0x87, 0x96, 0x36, 0x49, 0xb6, 0x14, 0xca, 0xaf, 0x22, 0x3c,
// //                  0xa7, 0x2a, 0xf2, 0xc4, 0x8d, 0x01, 0x40, 0x9a, 0xe4, 0x53, 0x8c, 0x6e, 0x6e, 0xb8, 0x1d, 0xa1, 0xa2, 0x86,
// //                  0x0f, 0x3a, 0xb9, 0x39, 0xb7, 0xbc, 0x46, 0x3c, 0x12, 0x9b, 0x0b, 0x26, 0xd1, 0xc6, 0xe9, 0x4a, 0xca, 0x93,
// //                  0x46, 0x9f, 0x2f, 0xd0, 0xd5, 0x52, 0x11, 0x16, 0xa9, 0xb9, 0x68, 0xf1, 0x7a, 0x4a, 0xcb, 0xa1, 0x63, 0x15,
// //                  0x0c, 0xe4, 0x3e, 0x11};
// //   bignum n;
// //   bignum_init(&n);

// //   char estr[] = {0x01, 0x00, 0x01};
// //   char dstr[] = {0x16, 0x6b, 0xc9, 0x0b, 0x2b, 0x1b, 0x63, 0x74, 0xf4, 0x65, 0x50, 0x9f, 0x5c, 0xdd, 0xbe, 0x1f,
// //                  0x1e, 0x29, 0xe7, 0x0a, 0x6b, 0x5d, 0xda, 0x27, 0x66, 0xd0, 0x48, 0xcd, 0x8c, 0xaa, 0x29, 0xdf, 0xc7,
// //                  0xc6, 0x3a, 0xd7, 0x81, 0x36, 0x43, 0x54, 0xda, 0x27, 0x71, 0xc2, 0x06, 0x41, 0xef, 0x93, 0x18, 0xae,
// //                  0xac, 0x13, 0xfe, 0xe2, 0xec, 0xa2, 0xaa, 0x28, 0xb0, 0xf7, 0x84, 0x6f, 0xf9, 0x7f, 0x0a, 0x34, 0xda,
// //                  0x3c, 0x79, 0x7c, 0xbd, 0xb8, 0x60, 0xd6, 0x31, 0xe4, 0x8c, 0xfb, 0x23, 0xaf, 0xbf, 0xf0, 0xa2, 0xc9,
// //                  0x98, 0x74, 0x03, 0x92, 0xec, 0x31, 0xd3, 0x3e, 0x1a, 0x83, 0x25, 0x9c, 0x9e, 0xc8, 0xf3, 0xa8, 0x55,
// //                  0xe3, 0x3a, 0xbd, 0xf3, 0x6c, 0xc0, 0xe5, 0xc1, 0x9c, 0xf6, 0x09, 0xb4, 0x79, 0xe5, 0x9f, 0xc7, 0x7e,
// //                  0x37, 0x01, 0xe6, 0x46, 0x60, 0x87, 0x0a, 0xb4, 0x50, 0x41};
// //   memcpy(key->n, nstr, 128);
// //   memset(key->e, 0, 128);
// //   memcpy(key->e, estr, 3);
// //   memcpy(key->d, dstr, 128);

// //   char ciphertext[128];
// //   rsa_encrypt(msg, 5, &key, ciphertext);


// //   memset(msg, 0, 128);
// //   rsa_decrypt(ciphertext, 128, &key, msg);
// // }

// int main() {
//   int num = 64;
//   rsa_key key;
//   rsa_init(&key);
//   FILE* fp = fopen("/home/gucx/123.txt", "r");
//   unsigned char buf[1024] = {0};
//   unsigned char out_buf[1024] = {0};
//   unsigned char tmp_buf[1024] = {0};
//   // fseek(fp, 128, SEEK_SET);
//   fread(buf, num, 1, fp);
//   fclose(fp);


//   print_bytes(buf, num);

//   rsa_encrypt(buf, out_buf, num, &key);
//   print_bytes(out_buf, num);

//   rsa_decrypt(out_buf, tmp_buf, num, &key);
//   print_bytes(tmp_buf, num);
// }
