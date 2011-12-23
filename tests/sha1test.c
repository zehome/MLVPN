#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main(int argc, char **argv)
{
    unsigned char sha1sum[SHA_DIGEST_LENGTH];
    unsigned char *p;
    int i;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s thestringtohash\n", argv[0]);
        return 1;
    }

    p = SHA1((unsigned char *)argv[1], strlen(argv[1]), sha1sum);
    if (! p)
    {
        fprintf(stderr, "Error in SHA1().\n");
        return 2;
    }

    printf("SHA1: ");
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        printf("%02x", sha1sum[i]);
    }

    printf("\n");
    return 0;
}
