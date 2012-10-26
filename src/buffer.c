#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "debug.h"
#include "mlvpn.h"

pktbuffer_t *
mlvpn_cb_init(int size)
{
    pktbuffer_t *buf = calloc(1, sizeof(pktbuffer_t));
    buf->size = size + 1; /* Add 1 element to know when we are full or empty */
    buf->pkts = (mlvpn_pkt_t *)calloc(buf->size, sizeof(mlvpn_pkt_t));
    mlvpn_cb_reset(buf);
    return buf;
}

void
mlvpn_cb_free(pktbuffer_t *buf)
{
    free(buf->pkts);
    free(buf);
}

/* Re-initialize the ring buffer to default values */
void
mlvpn_cb_reset(pktbuffer_t *buf)
{
    buf->start = 0;
    buf->end = 0;
    buf->bandwidth = 0;
}

int
mlvpn_cb_is_full(pktbuffer_t *buf)
{
    return (buf->end + 1) % buf->size == buf->start;
}

int
mlvpn_cb_is_empty(pktbuffer_t *buf)
{
    return buf->end == buf->start;
}

/* Release and return the packet if available. */
mlvpn_pkt_t *
mlvpn_cb_read(pktbuffer_t *buf)
{
    mlvpn_pkt_t *pkt;
    pkt = &buf->pkts[buf->start];
    buf->start = (buf->start + 1) % buf->size;
    return pkt;
}

/* Return the packet if available. (NO RELEASE) */
mlvpn_pkt_t *
mlvpn_cb_read_norelease(pktbuffer_t *buf)
{
    mlvpn_pkt_t *pkt;
    pkt = &buf->pkts[buf->start];
    return pkt;
}

/* Register & return a new packet. */
mlvpn_pkt_t *
mlvpn_cb_write(pktbuffer_t *buf)
{
    mlvpn_pkt_t *pkt = &buf->pkts[buf->end];
    buf->end = (buf->end + 1) % buf->size;
    if (buf->end == buf->start)
    {
        /* Should not go there (overwrite) */
        buf->start = (buf->start + 1) % buf->size;
    }
    /* Initialize the new packet to send */
    pkt->pktdata.magic = MLVPN_MAGIC;
    pkt->next_packet_send = 0;
    return pkt;
}
