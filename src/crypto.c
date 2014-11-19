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
    return crypto_generichash(key, sizeof key, (unsigned char *)password,
                              password_len, NULL, 0);
}

int crypto_encrypt(unsigned char *c, const unsigned char *m,
                   unsigned long long mlen)
{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    int r;
    randombytes_buf(nonce, sizeof nonce);
    r = crypto_secretbox_easy(c, m, mlen, nonce, key);
    if (r == 0) {
        memcpy(c + sizeof nonce, nonce, sizeof nonce);
    }
    return r;
}

int crypto_decrypt(unsigned char *d, const unsigned char *c,
                   unsigned long long clen)
{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, c + sizeof nonce, sizeof nonce);
    return crypto_secretbox_open_easy(d, c, clen, nonce, key);
}
