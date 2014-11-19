#ifndef _MLVPN_BUFFER_H
#define _MLVPN_BUFFER_H

#include <sys/types.h>

#include "pkt.h"

/* Basic circular buffer
 * data can be stored inside the struct, but that's not mandatory.
 * data is not used directly by mlvpn_cb_*.
 */
typedef struct
{
    int size;
    int start;
    int end;
    void *data;
} circular_buffer_t;

typedef struct
{
    uint32_t bandwidth;
    mlvpn_pkt_t **pkts;
} pktbuffer_t;


/**
 * Generic circular buffer handling
 */

/* Allocate a circular of size +1 element of sizememb length */
circular_buffer_t *
mlvpn_cb_init(int size);

void
mlvpn_cb_free(circular_buffer_t *buf);

void
mlvpn_cb_reset(circular_buffer_t *buf);

int
mlvpn_cb_is_full(const circular_buffer_t *buf);

int
mlvpn_cb_is_empty(const circular_buffer_t *buf);

void *
mlvpn_cb_read(circular_buffer_t *buf, void **data);

void *
mlvpn_cb_read_norelease(const circular_buffer_t *buf, void **data);

void *
mlvpn_cb_write(circular_buffer_t *buf, void **data);

/**
 * Application specific cirtular buffer handlers
 */

#define mlvpn_pktbuffer_bandwidth(buf) ((pktbuffer_t *)buf->data)->bandwidth

circular_buffer_t *
mlvpn_pktbuffer_init(int size);

void
mlvpn_pktbuffer_free(circular_buffer_t *buf);

void
mlvpn_pktbuffer_reset(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_read(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_read_norelease(circular_buffer_t *buf);

mlvpn_pkt_t *
mlvpn_pktbuffer_write(circular_buffer_t *buf);

#endif
