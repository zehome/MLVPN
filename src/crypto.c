#include "debug.h"
#include "crypto.h"
#include <string.h>

static unsigned char key[crypto_secretbox_KEYBYTES];


int crypto_init()
{
    return sodium_init();
}

int crypto_set_password(const char *password,
                        unsigned long long password_len)
{
    return crypto_generichash(
        key, sizeof(key), (unsigned char *)password, password_len, NULL, 0);
}

int crypto_encrypt(unsigned char *c, const unsigned char *m,
                   unsigned long long mlen,
                   const unsigned char *nonce)
{
    return crypto_secretbox_easy(c, m, mlen, nonce, key);
}

int crypto_decrypt(unsigned char *m, const unsigned char *c,
                   unsigned long long clen,
                   const unsigned char *nonce)
{
    return crypto_secretbox_open_easy(m, c, clen, nonce, key);
}

void crypto_nonce_random(unsigned char *nonce, int len)
{
    randombytes_buf(nonce, len);
}