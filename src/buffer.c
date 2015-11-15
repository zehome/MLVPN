/*
 * Copyright (c) 2015, Laurent COUSTET <ed@zehome.com>
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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


freebuffer_t *
mlvpn_freebuffer_init(unsigned int size)
{
    unsigned int i;
    struct pkt_entry *entry;
    freebuffer_t *freebuf = calloc(size, sizeof(freebuffer_t));
    if (freebuf == NULL) {
        fatal("buffer", "memory allocation failed");
    }
    freebuf->size = size;
    freebuf->used = 0;
    TAILQ_INIT(&freebuf->free_head);
    TAILQ_INIT(&freebuf->used_head);
    for(i = 0; i < size; i++) {
        entry = calloc(1, sizeof(struct pkt_entry));
        if (entry == NULL) {
            fatal("buffer", "memory allocation failed");
        }
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
    }
    return freebuf;
}

void
mlvpn_freebuffer_reset(freebuffer_t *freebuf) 
{
    struct pkt_entry *entry;
    while(!TAILQ_EMPTY(&freebuf->used_head)) {
        entry = TAILQ_FIRST(&freebuf->used_head);
        TAILQ_REMOVE(&freebuf->used_head, entry, entries);
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
    }
    freebuf->used = 0;
}

mlvpn_pkt_t *
mlvpn_freebuffer_get(freebuffer_t *freebuf)
{
    struct pkt_entry *entry = TAILQ_FIRST(&freebuf->free_head);
    if (entry) {
        TAILQ_REMOVE(&freebuf->free_head, entry, entries);
        TAILQ_INSERT_TAIL(&freebuf->used_head, entry, entries);
        freebuf->used++;
        return &entry->pkt;
    } else {
        return NULL;
    }
}

mlvpn_pkt_t *
mlvpn_freebuffer_drain_used(freebuffer_t *freebuf)
{
    /* We get the elements in reverse order there... Not ideal */
    struct pkt_entry *entry = TAILQ_FIRST(&freebuf->used_head);
    if (entry) {
        TAILQ_REMOVE(&freebuf->used_head, entry, entries);
        TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
        freebuf->used--;
        return &entry->pkt;
    } else {
        return NULL;
    }
}

void
mlvpn_freebuffer_free(freebuffer_t *freebuf, mlvpn_pkt_t *pkt)
{
    struct pkt_entry *entry;
    mlvpn_pkt_t *p;
    TAILQ_FOREACH(entry, &freebuf->used_head, entries)
    {
        p = &entry->pkt;
        if (p == pkt) {
            TAILQ_REMOVE(&freebuf->used_head, entry, entries);
            TAILQ_INSERT_HEAD(&freebuf->free_head, entry, entries);
            freebuf->used--;
            return;
        }
    }
    fatalx("freebuffer_free could not find the packet you gave me.");
}