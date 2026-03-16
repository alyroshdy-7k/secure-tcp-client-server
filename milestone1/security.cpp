#include <string.h>
#include "security.h"

void xor_encrypt_decrypt(char *data, int len, const char *key)
{
    int key_len = strlen(key);

    for(int i = 0; i < len; i++)
    {
        data[i] = data[i] ^ key[i % key_len];
    }
}
