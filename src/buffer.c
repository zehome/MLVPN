#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "debug.h"
#include "mlvpn.h"

/* Build a new pkt and insert into pktbuffer */
int
mlvpn_put_pkt(pktbuffer_t *buf, const void *data, size_t len)
{
    mlvpn_pkt_t pkt;
    if (len > MAX_PKT_LEN)
    {
        _ERROR("Packet len %u overlimit %u. MTU too high.\n", 
            (uint32_t)len, (uint32_t) MAX_PKT_LEN);
        return -1;
    }
    pkt.pktdata.magic = MLVPN_MAGIC;
    pkt.pktdata.len = len;
    pkt.next_packet_send = 0;

    memcpy(pkt.pktdata.data, data, len);
    memcpy(&buf->pkts[buf->len], &pkt, sizeof(mlvpn_pkt_t));
    return ++buf->len;
}

void
mlvpn_pop_pkt(pktbuffer_t *buf)
{
    int i;
    for (i = 0; i < buf->len-1; i++)
        memmove(&buf->pkts[i], &buf->pkts[i+1], sizeof(mlvpn_pkt_t));
    buf->len -= 1;
}

