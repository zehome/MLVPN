#ifndef _MLVPN_BUFFER_H
#define _MLVPN_BUFFER_H

#include <sys/types.h>
#include <sys/queue.h>
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
    mlvpn_pkt_t **pkts;
} pktbuffer_t;


struct pkt_entry {
    mlvpn_pkt_t pkt;
    TAILQ_ENTRY(pkt_entry) entries;
};

typedef struct {
    uint32_t size;
    uint32_t used;
    TAILQ_HEAD(, pkt_entry) free_head;
    TAILQ_HEAD(, pkt_entry) used_head;
} freebuffer_t;

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


/**
 * Single allocation buffers (used for reordering)
 */
freebuffer_t *
mlvpn_freebuffer_init(uint32_t size);

void
mlvpn_freebuffer_reset(freebuffer_t *freebuf);

mlvpn_pkt_t *
mlvpn_freebuffer_get(freebuffer_t *freebuf);

void
mlvpn_freebuffer_free(freebuffer_t *freebuf, mlvpn_pkt_t *pkt);

mlvpn_pkt_t *
mlvpn_freebuffer_drain_used(freebuffer_t *freebuf);

#endif
