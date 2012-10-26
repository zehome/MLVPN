#ifndef _MLVPN_BUFFER_H
#define _MLVPN_BUFFER_H

#include <sys/types.h>

#include "pkt.h"

typedef struct pktbuffer_s
{
    int size;
    int start;
    int end;
    /* This represents the bandwidth to use on this queue
     * in bytes per second.
     * Set to <= 0 for not limiting bandwidth.
     *
     * The above flag is calculated from the bandwidth
     * using the following formula:
     * next_packet_send = now_in_millis + 1/(bandwidth/packetlen)
     */
    uint32_t bandwidth;
    mlvpn_pkt_t *pkts;
} pktbuffer_t;

pktbuffer_t *
mlvpn_cb_init(int size);

void
mlvpn_cb_free(pktbuffer_t *buf);

void
mlvpn_cb_reset(pktbuffer_t *buf);

int
mlvpn_cb_is_full(pktbuffer_t *buf);

int
mlvpn_cb_is_empty(pktbuffer_t *buf);

mlvpn_pkt_t *
mlvpn_cb_read(pktbuffer_t *buf);

mlvpn_pkt_t *
mlvpn_cb_read_norelease(pktbuffer_t *buf);

mlvpn_pkt_t *
mlvpn_cb_write(pktbuffer_t *buf);

#endif
