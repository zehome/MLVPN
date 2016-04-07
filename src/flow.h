#ifndef MLVPN_FLOW_H
#define MLVPN_FLOW_H

#include "includes.h"
#include "reorder.h"

struct mlvpn_flow {
    u_int32_t src_ip;
    u_int32_t dest_ip;
    u_int32_t src_port;
    u_int32_t dest_port;
    u_int32_t seq;
    ev_tstamp expires;
    TAILQ_ENTRY(mlvpn_flow) entries;
    struct mlvpn_reorder_buffer *reorder;
    ev_timer  reorder_timeout;
    u_int8_t  protocol;
    u_int8_t  pad1;
    u_int16_t pad2;
} __attribute__((__packed__));

void mlvpn_flowlist_init();
void mlvpn_flowlist_free();
struct mlvpn_flow *mlvpn_flow_new(const struct mlvpn_flow *inflow);
struct mlvpn_flow *mlvpn_flow_find(const struct mlvpn_flow *inflow);
void mlvpn_flow_remove(struct mlvpn_flow *flow);

#endif