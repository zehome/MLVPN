#ifndef MLVPN_CHAP_H
#define MLVPN_CHAP_H

#include <openssl/sha.h>

#define MLVPN_CHAP_DIGEST SHA_DIGEST_LENGTH
#define MLVPN_CHAP_MAX 128
#define MLVPN_CHALLENGE_MAX 256

enum {
    MLVPN_CHAP_DISCONNECTED,
    MLVPN_CHAP_AUTHSENT,
    MLVPN_CHAP_AUTHOK
};

void
mlvpn_compute_challenge(char *password, char *challenge, int len,
    unsigned char *sha1sum);

#endif
