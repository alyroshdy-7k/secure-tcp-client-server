#include "security.h"

void aes_encrypt(unsigned char *plaintext, int len, unsigned char *ciphertext) {
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char*)AES_KEY_TEXT, 128, &enc_key);
    for (int i = 0; i < len; i += 16) {
        AES_encrypt(plaintext + i, ciphertext + i, &enc_key);
    }
}

void aes_decrypt(unsigned char *ciphertext, int len, unsigned char *plaintext) {
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char*)AES_KEY_TEXT, 128, &dec_key);
    for (int i = 0; i < len; i += 16) {
        AES_decrypt(ciphertext + i, plaintext + i, &dec_key);
    }
}
