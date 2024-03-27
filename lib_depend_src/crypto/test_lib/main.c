#include "pkc/rsa.h"
#include "cipher/aes.h"
#include "cipher/des.h"
#include "cipher_modes/ecb.h"
#include "rng/yarrow.h"
#include "malloc.h"
#include "syscall.h"
#include "string.h"

void printBytes(const char* msg, unsigned long len) {
    for (int i = 0; i < len; i++) {
        ks_printf(1, "0x%x(", (unsigned char)(msg[i]));
        ks_printf(1, "%d) ", (unsigned char)(msg[i]));
    }
    ks_printf(1, "%s", "\n");
}

YarrowContext yarrowContext;

int main() {
    ks_malloc_init();
    /*
        RSA Test
    */
    // uint8_t seed[32];
    // yarrowInit(&yarrowContext);
    // yarrowSeed(&yarrowContext, seed, sizeof(seed));

    // RsaPublicKey publicKey;
    // RsaPrivateKey privateKey;
    // rsaInitPublicKey(&publicKey);
    // rsaInitPrivateKey(&privateKey);
    // rsaGenerateKeyPair(&yarrowPrngAlgo, &yarrowContext, 2048, 65537, &privateKey, &publicKey);

    // char msg[500];
    // // char msg[] = "who are you?";
    // char cipher[1024] = {0};
    // char res[1024] = {0};
    // size_t msg_len = 500;
    // size_t message_len;
    // size_t cipher_len;
    // osMemset(msg, 'a', 500);
    // int offset = 0;
    // while (offset + 245 < msg_len) {
    //     rsaesPkcs1v15Encrypt(&yarrowPrngAlgo, &yarrowContext, &publicKey, msg + offset, 245, cipher + offset, &cipher_len);
    //     ks_printf(1, "cipherlen: %d : \n", cipher_len);
    //     printBytes(cipher + offset, cipher_len);
    //     rsaesPkcs1v15Decrypt(&privateKey, cipher + offset, cipher_len, res + offset, 1024 - offset, &message_len);
    //     ks_printf(1, "plaintext len : %d : \n", message_len);
    //     printBytes(res + offset, message_len);
    //     offset += 245;
    // }
    // rsaesPkcs1v15Encrypt(&yarrowPrngAlgo, &yarrowContext, &publicKey, msg + offset, msg_len - offset, cipher + offset, &cipher_len);
    // ks_printf(1, "cipherlen: %d : \n", cipher_len);
    // printBytes(cipher + offset, cipher_len);
    // rsaesPkcs1v15Decrypt(&privateKey, cipher + offset, cipher_len, res + offset, 1024, &message_len);
    // ks_printf(1, "plaintext len : %d : \n", message_len);
    // printBytes(res + offset, message_len);

    /*
        AES Test
    */
    // AesContext aes_context;
    // uint8_t aes_key[] = "0123456789abcdef";
    // aesInit(&aes_context, aes_key, 16);

    // char msg[] = "0123456789012345";
    // char buff[256] = {0};
    // char res[128] = {0};
    // aesEncryptBlock(&aes_context, msg, buff);
    // // printBytes(buff, 256);
    // aesDecryptBlock(&aes_context, buff, res);
    // printBytes(res, 128);

    /*
        DES Test
    */
    // DesContext des_context;
    // uint8_t des_key[] = "01234567";
    // desInit(&des_context, des_key, 8);

    // char msg[] = "01234567";
    // ks_printf(1, "plain text len: %d\n", osStrlen(msg));
    // printBytes(msg, osStrlen(msg));
    // char buff[256] = {0};
    // char res[256] = {0};
    // desEncryptBlock(&des_context, msg, buff);
    // printBytes(buff, 256);
    // desDecryptBlock(&des_context, buff, res);
    // printBytes(res, 256);

    /*
        ECB-DES Test
    */
    DesContext des_context;
    uint8_t des_key[] = "01234567";
    desInit(&des_context, des_key, 8);

    char msg[] = "0123456776543210";
    ks_printf(1, "plain text len: %d\n", osStrlen(msg));
    printBytes(msg, osStrlen(msg));
    char buff[256] = {0};
    char res[256] = {0};
    ecbEncrypt(&desCipherAlgo, &des_context, msg, buff, 16);
    printBytes(buff, 256);
    ecbDecrypt(&desCipherAlgo, &des_context, buff, res, 16);
    printBytes(res, 256);

    ks_malloc_deinit();
    sys_exit(0);
}