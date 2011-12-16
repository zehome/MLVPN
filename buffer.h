#ifndef _MLVPN_BUFFER_H
#define _MLVPN_BUFFER_H

#include <sys/types.h>

#include "pkt.h"

typedef struct pktbuffer_s
{
    size_t len;
    mlvpn_pkt_t *pkts;
    /* This represents the bandwidth to use on this queue
     * in bytes per second.
     * Set to <= 0 for not limiting bandwidth.
     *
     * The above flag is calculated from the bandwidth
     * using the following formula:
     * next_packet_send = now_in_millis + 1/(bandwidth/packetlen)
     */
    uint32_t bandwidth;
} pktbuffer_t;

int
mlvpn_put_pkt(pktbuffer_t *buf, const void *data, size_t len);

void
mlvpn_pop_pkt(pktbuffer_t *buf);

#endif
