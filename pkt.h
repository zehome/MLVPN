#ifndef _MLVPN_PKT_H
#define _MLVPN_PKT_H

#include <stdint.h>

/* TCP overhead = 66 Bytes on the wire */
#define DEFAULT_MTU 1500
#define TCP_OVERHEAD 66
#define TUNTAP_RW_MAX DEFAULT_MTU
#define RTUN_RW_MAX (DEFAULT_MTU - TCP_OVERHEAD)
#define MAX_PKT_LEN 1500

struct mlvpn_pktdata
{
    uint32_t magic;
    uint32_t len;
    char data[DEFAULT_MTU];
};
#define PKTHDRSIZ(pktdata) (sizeof(pktdata)-sizeof(pktdata.data))

typedef struct mlvpn_pkt
{
    struct mlvpn_pktdata pktdata;
    /* This variable permits to "sleep" some time before
     * sending a new packet.
     * This is used to permit trafic shaping
     * on the "bulk" queue (sbuf not on hpsbuf)
     */
    uint64_t next_packet_send;
} mlvpn_pkt_t;

#endif
