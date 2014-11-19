#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>

/* TCP overhead = 66 Bytes on the wire */
#define DEFAULT_MTU 1500
#define MAX_PKT_LEN 1500

enum {
	MLVPN_PKT_AUTH,
	MLVPN_PKT_AUTH_OK,
	MLVPN_PKT_KEEPALIVE,
	MLVPN_PKT_DATA
};

struct mlvpn_pktdata
{
    uint16_t len;
    char type;
    char data[DEFAULT_MTU];
} __attribute__((packed));

#define PKTHDRSIZ(pktdata) (sizeof(pktdata)-sizeof(pktdata.data))

typedef struct mlvpn_pkt
{
    struct mlvpn_pktdata pktdata;
} mlvpn_pkt_t;

#endif
