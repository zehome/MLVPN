#include "debug.h"
#include "crypto.h"
#include <string.h>

static unsigned char key[crypto_secretbox_KEYBYTES];

static void print_key()
{
    int i;
    printf("KEY(%d): ", crypto_secretbox_KEYBYTES);
    for(i = 0; i < sizeof key; i++) {
        printf("%02x ", key[i]);
    }
    printf("\n");
}

static void print_nonce(const unsigned char *nonce)
{
    int i;
    printf("NONCE(%d): ", crypto_secretbox_NONCEBYTES);
    for(i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
        printf("%02x ", nonce[i]);
    }
    printf("\n");
}

static void print_data(const unsigned char *p, int plen)
{
    int i;
    printf("DATA: ");
    for(i=0;i<plen;i++) printf("%02x ", p[i]);
    printf("\n");
}

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
    print_key();
    //randombytes_buf(nonce, sizeof nonce);
    memset(nonce, 0, sizeof nonce);
    //print_nonce((unsigned char*)&nonce);
    r = crypto_secretbox_easy(c, m, mlen, nonce, key);
    print_data(c, mlen + crypto_PADSIZE);
    // if (r == 0) {
    //     memcpy(c + sizeof nonce, nonce, sizeof nonce);
    // }
    return r;
}

int crypto_decrypt(unsigned char *m, const unsigned char *c,
                   unsigned long long clen)
{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    //memcpy(nonce, c + sizeof nonce, sizeof nonce);
    memset(nonce, 0, sizeof nonce);
    print_key();
    //print_nonce((unsigned char*)&nonce);
    print_data(c, clen);
    int ret = crypto_secretbox_open_easy(m, c, clen, nonce, key);
    return ret;
}

