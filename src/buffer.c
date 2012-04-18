#include <stdlib.h>
#include <string.h>

#include "buffer.h"
#include "debug.h"
#include "mlvpn.h"

/* checks the selected pktbuffer if a packet can be inserted
 * returns 0 on success
 * returns -1 on error
 * if the reset flag is set to 1, then the buffer is flushed
 */
int
mlvpn_check_buffer(pktbuffer_t *buf, int reset)
{
    if (buf->len > PKTBUFSIZE)
    {
        if (reset)
            buf->len = 0;
        return -1;
    }
    return 0;
}

/* Returns the next free mlvpn_pkt_t* */
mlvpn_pkt_t *
mlvpn_get_free_pkt(pktbuffer_t *buf)
{
    mlvpn_pkt_t *pkt = &buf->pkts[buf->len++];
    pkt->pktdata.magic = MLVPN_MAGIC;
    pkt->next_packet_send = 0;
    return pkt;
}

/* TODO: find a better way to do that! */
void
mlvpn_pop_pkt(pktbuffer_t *buf)
{
    int i;
    for (i = 0; i < buf->len-1; i++)
        memmove(&buf->pkts[i], &buf->pkts[i+1], sizeof(mlvpn_pkt_t));
    buf->len -= 1;
}

