#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "mlvpn.h"

/**
  * Generic handlers
  */

circular_buffer_t *
mlvpn_cb_init(int size)
{
    circular_buffer_t *buf = calloc(1, sizeof(circular_buffer_t));
    buf->size = size + 1; /* Add 1 element to know when we are full or empty */
    buf->data = NULL;
    mlvpn_cb_reset(buf);
    return buf;
}

/* Please note you MUST free yourself the data associated! */
void
mlvpn_cb_free(circular_buffer_t *buf)
{
    free(buf);
}

/* Re-initialize the ring buffer to default values */
void
mlvpn_cb_reset(circular_buffer_t *buf)
{
    buf->start = 0;
    buf->end = 0;
}

int
mlvpn_cb_is_full(const circular_buffer_t *buf)
{
    return (buf->end + 1) % buf->size == buf->start;
}

int
mlvpn_cb_is_empty(const circular_buffer_t *buf)
{
    return buf->end == buf->start;
}

/* Release and return the packet if available.
 * data must point to a valid location in memory
 * where the actual data is stored.
*/
void *
mlvpn_cb_read(circular_buffer_t *buf, void **data)
{
    void *ret = data[buf->start];
    buf->start = (buf->start + 1) % buf->size;
    return ret;
}


/* Register & return a new packet.
 * See comment in cb_read for **data signification.
 */
void *
mlvpn_cb_write(circular_buffer_t *buf, void **data)
{
    void *ret = data[buf->end];
    buf->end = (buf->end + 1) % buf->size;
    if (buf->end == buf->start)
        buf->start = (buf->start + 1) % buf->size;
    return ret;
}

/**
 * Application specific handlers
 */
circular_buffer_t *
mlvpn_pktbuffer_init(int size)
{
    int i;
    /* Basic circular buffer allocation */
    circular_buffer_t *buf = mlvpn_cb_init(size);

    /* Actual packet buffer memory allocation */
    pktbuffer_t *pktbuf = calloc(1, sizeof(pktbuffer_t));
    pktbuf->pkts = malloc(buf->size * sizeof(mlvpn_pkt_t *));
    for(i = 0; i < buf->size; i++)
        pktbuf->pkts[i] = calloc(1, sizeof(mlvpn_pkt_t));

    buf->data = pktbuf;
    /* This is sub-optimal as we call cb_free another time.
     * Not a big deal though. */
    mlvpn_pktbuffer_reset(buf);
    return buf;
}

void
mlvpn_pktbuffer_free(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    free(pktbuffer->pkts);
    mlvpn_cb_free(buf);
}

void
mlvpn_pktbuffer_reset(circular_buffer_t *buf)
{
    mlvpn_cb_reset(buf);
}

mlvpn_pkt_t *
mlvpn_pktbuffer_write(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    mlvpn_pkt_t *pkt = (mlvpn_pkt_t *)mlvpn_cb_write(buf,
                       (void *)pktbuffer->pkts);
    /* Initialize the new packet to send */
    pkt->len = 0;
    pkt->type = MLVPN_PKT_DATA;
    return pkt;
}

mlvpn_pkt_t *
mlvpn_pktbuffer_read(circular_buffer_t *buf)
{
    pktbuffer_t *pktbuffer = buf->data;
    return (mlvpn_pkt_t *)mlvpn_cb_read(buf,
                                        (void *)pktbuffer->pkts);
}
