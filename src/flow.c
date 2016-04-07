#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ev.h>
#include "flow.h"
#include "log.h"

static TAILQ_HEAD(, mlvpn_flow) flows_head;

void
mlvpn_flowlist_init()
{
    TAILQ_INIT(&flows_head);
}

void
mlvpn_flowlist_free()
{
    struct mlvpn_flow *flow, *tmpflow;
    flow = tmpflow = NULL;
    TAILQ_FOREACH_SAFE(flow, &flows_head, entries, tmpflow) {
        mlvpn_flow_remove(flow);
    }
}

inline static void
mlvpn_flow_tick(struct mlvpn_flow *flow)
{
    /* TODO: why 5 minutes timeout ? */
    flow->expires = ev_now(EV_DEFAULT_UC) + 300.0;
}

struct mlvpn_flow *
mlvpn_flow_find(const struct mlvpn_flow *inflow)
{
    struct mlvpn_flow *flow, *tmpflow;
    flow = tmpflow = NULL;
    TAILQ_FOREACH_SAFE(flow, &flows_head, entries, tmpflow) {
        if (flow->src_ip == inflow->src_ip &&
            flow->dest_ip == inflow->dest_ip &&
            flow->protocol == inflow->protocol &&
            flow->src_port == inflow->src_port &&
            flow->dest_port == inflow->dest_port) {
            mlvpn_flow_tick(flow);
            return flow;
        } else if (flow->expires < ev_now(EV_DEFAULT_UC)) {
            log_debug("flow", "remove expired flow");
            mlvpn_flow_remove(flow);
        }
    }
    return NULL;
}

struct mlvpn_flow *
mlvpn_flow_new(const struct mlvpn_flow *inflow)
{
    struct mlvpn_flow *flow;
    flow = calloc(1, sizeof(struct mlvpn_flow));
    if (!flow)
        fatal(NULL, "calloc");
    /* TODO: use config */
    flow->reorder = mlvpn_reorder_create(1024);
    flow->reorder_timeout.data = flow;
    flow->src_ip = inflow->src_ip;
    flow->dest_ip = inflow->dest_ip;
    flow->protocol = inflow->protocol;
    flow->src_port = inflow->src_port;
    flow->dest_port = inflow->dest_port;
    {
        struct in_addr src;
        struct in_addr dest;
        char src_h[32], dest_h[32];
        src.s_addr = inflow->src_ip;
        dest.s_addr = inflow->dest_ip;
        strlcpy(src_h, inet_ntoa(src), sizeof(src_h));
        strlcpy(dest_h, inet_ntoa(dest), sizeof(dest_h));
        log_debug("flow", "new flow prot=%"PRIu32" %s:%u -> %s:%u",
            flow->protocol,
            src_h, be16toh(flow->src_port),
            dest_h, be16toh(flow->dest_port));
    }
    mlvpn_flow_tick(flow);
    TAILQ_INSERT_TAIL(&flows_head, flow, entries);
    return flow;
}

void
mlvpn_flow_remove(struct mlvpn_flow *flow)
{
    ev_timer_stop(EV_DEFAULT_UC, &flow->reorder_timeout);
    mlvpn_reorder_free(flow->reorder);
    TAILQ_REMOVE(&flows_head, flow, entries);
    free(flow);
}
