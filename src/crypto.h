#ifndef MLVPN_CRYPTO_H
#define MLVPN_CRYPTO_H

#include <sodium.h>
#define crypto_PADSIZE crypto_secretbox_MACBYTES
#define ENABLE_CRYPTO

int crypto_init();
int crypto_set_password(const char *password,
                        unsigned long long password_len);
int crypto_encrypt(unsigned char *c, const unsigned char *m,
                   unsigned long long mlen);
int crypto_decrypt(unsigned char *m, const unsigned char *c,
                   unsigned long long clen);

#endif