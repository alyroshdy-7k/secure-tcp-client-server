#ifndef SECURITY_H
#define SECURITY_H
#include <openssl/aes.h>
#include <string.h>

#define AES_KEY_TEXT "1234567890123456"

void aes_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext);
void aes_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext);
#endif
