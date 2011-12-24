#include <openssl/sha.h>
#include <string.h>

#include "mlvpn.h"
#include "chap.h"

void
mlvpn_compute_challenge(char *password, char *challenge, int len,
    unsigned char *sha1sum)
{
    /* Concatenate password with challenge, then sha1sum */
    char answer[MLVPN_CHALLENGE_MAX+MLVPN_CHAP_MAX+1];
    memset(answer, 0, sizeof(answer));
    strncat(answer, password, MLVPN_CHAP_MAX);
    strncat(answer, challenge, MLVPN_CHALLENGE_MAX+MLVPN_CHAP_MAX);
    SHA1((unsigned char *)answer, strlen(answer), sha1sum);
}
