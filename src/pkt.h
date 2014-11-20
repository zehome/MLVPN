#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>
#include "crypto.h"

/* TCP overhead = 66 Bytes on the wire */
#define DEFAULT_MTU 1500
#define MAX_PKT_LEN 1500

enum {
	MLVPN_PKT_AUTH,
	MLVPN_PKT_AUTH_OK,
	MLVPN_PKT_KEEPALIVE,
	MLVPN_PKT_DATA
};

typedef struct {
    uint16_t len;
    uint8_t type;
    char data[DEFAULT_MTU];
} mlvpn_pkt_t;

typedef struct {
    uint16_t len;
	unsigned char flags;
	unsigned char nonce[crypto_NONCEBYTES];
	char data[DEFAULT_MTU];
} __attribute__((packed)) mlvpn_proto_t;

#define PKTHDRSIZ(pkt) (sizeof(pkt)-sizeof(pkt.data))

#endif
