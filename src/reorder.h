/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *   Adapted for mlvpn by Laurent Coustet (c) 2015
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MLVPN_REORDER_H
#define MLVPN_REORDER_H

#include "pkt.h"

/**
 * @file
 * mlvpn reorder
 *
 * Reorder library is a component which is designed to
 * provide ordering of out of ordered packets based on
 * sequence number present in pkt.
 *
 */


struct mlvpn_reorder_buffer;

/**
 * Create a new reorder buffer instance
 *
 * Allocate memory and initialize a new reorder buffer in that
 * memory, returning the reorder buffer pointer to the user
 * @param size
 *   Max number of elements that can be stored in the reorder buffer
 * @return
 *   The initialized reorder buffer instance, or NULL on error
 *   On error case, mlvpn_errno will be set appropriately:
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 *    - EINVAL - invalid parameters
 */
struct mlvpn_reorder_buffer *
mlvpn_reorder_create(unsigned int size);

/**
 * Initializes given reorder buffer instance
 *
 * @param b
 *   Reorder buffer instance to initialize
 * @param bufsize
 *   Size of the reorder buffer
 * @param size
 *   Number of elements that can be stored in reorder buffer
 * @return
 *   The initialized reorder buffer instance, or NULL on error
 *   On error case, mlvpn_errno will be set appropriately:
 *    - EINVAL - invalid parameters
 */
struct mlvpn_reorder_buffer *
mlvpn_reorder_init(struct mlvpn_reorder_buffer *b, unsigned int bufsize,
    unsigned int size);

/**
 * Reset the given reorder buffer instance with initial values.
 *
 * @param b
 *   Reorder buffer instance which has to be reset
 */
void
mlvpn_reorder_reset(struct mlvpn_reorder_buffer *b);

/**
 * Free reorder buffer instance.
 *
 * @param b
 *   reorder buffer instance
 * @return
 *   None
 */
void
mlvpn_reorder_free(struct mlvpn_reorder_buffer *b);

/**
 * Insert given pkt in reorder buffer in its correct position
 *
 * The given pkt is to be reordered relative to other pkts in the system.
 * The pkt must contain a sequence number which is then used to place
 * the buffer in the correct position in the reorder buffer. Reordered
 * packets can later be taken from the buffer using the mlvpn_reorder_drain()
 * API.
 *
 * @param b
 *   Reorder buffer where the pkt has to be insemlvpnd.
 * @param pkt
 *   pkt that needs to be inserted in reorder buffer.
 * @return
 *   0 on success
 *   -1 on error
 *   On error case, mlvpn_errno will be set appropriately:
 *    - ENOSPC - Cannot move existing pkts from reorder buffer to accommodate
 *      ealry pkt, but it can be accomodated by performing drain and then insert.
 *    - ERANGE - Too early or late pkt which is vastly out of range of expected
 *      window should be ingnored without any handling.
 */
int
mlvpn_reorder_insert(struct mlvpn_reorder_buffer *b, mlvpn_pkt_t *pkt);

/**
 * Fetch reordered buffers
 *
 * Returns a set of in-order buffers from the reorder buffer structure. Gaps
 * may be present in the sequence numbers of the pkt if packets have been
 * delayed too long before reaching the reorder window, or have been previously
 * dropped by the system.
 *
 * @param b
 *   Reorder buffer instance from which packets are to be drained
 * @param pkts
 *   array of pkts where reordered packets will be insemlvpnd from reorder buffer
 * @param max_pkts
 *   the number of elements in the pkts array.
 * @return
 *   number of pkt pointers written to pkts. 0 <= N < max_pkts.
 */
unsigned int
mlvpn_reorder_drain(struct mlvpn_reorder_buffer *b, mlvpn_pkt_t **pkts,
        unsigned max_pkts);

#endif /* MLVPN_REORDER_H */
