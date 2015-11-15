#ifndef MLVPN_CRYPTO_H
#define MLVPN_CRYPTO_H

#include <sodium.h>
#define crypto_PADSIZE crypto_secretbox_MACBYTES
#define crypto_NONCEBYTES crypto_secretbox_NONCEBYTES
#define ENABLE_CRYPTO

int crypto_init();
int crypto_set_password(const char *password,
                        unsigned long long password_len);
int crypto_encrypt(unsigned char *c, const unsigned char *m,
                   unsigned long long mlen,
                   const unsigned char *nonce);
int crypto_decrypt(unsigned char *m, const unsigned char *c,
                   unsigned long long clen,
                   const unsigned char *nonce);
#define crypto_nonce_random randombytes_random

#endif
