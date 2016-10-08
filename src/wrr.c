#include "mlvpn.h"

/* Fairly big no ? */
#define MAX_TUNNELS 128

struct mlvpn_wrr {
    int len;
    mlvpn_tunnel_t *tunnel[MAX_TUNNELS];
    double tunval[MAX_TUNNELS];
};

static struct mlvpn_wrr wrr = {
    0,
    {NULL},
    {0}
};

static int wrr_min_index()
{
    double min = 100.0;
    int min_index = 0;
    int i;

    for(i = 0; i < wrr.len; i++)
    {
        if (wrr.tunval[i] < min)
        {
            min = wrr.tunval[i];
            min_index = i;
        }
    }
    return min_index;
}

/* initialize wrr system */
int mlvpn_rtun_wrr_reset(struct rtunhead *head, int use_fallbacks)
{
    int tunnels = 0;
    mlvpn_tunnel_t *t;
    // TODO: add tunnels in the right order to |head| to begin with
    log_debug("wrr_reset", "begin");
    LIST_FOREACH(t, head, entries) {
        log_debug("wrr_reset", "checking tunnel");
        if (t->fallback_only != use_fallbacks) {
            continue;
        }
        /* Don't select "LOSSY" tunnels, except if we are in fallback mode */
        if ((t->fallback_only && t->status >= MLVPN_AUTHOK) ||
            (t->status == MLVPN_AUTHOK))
        {
            tunnels++;
        }
    }
    log_debug("wrr_reset", "done, found %d tunnels", tunnels);
    wrr.len = tunnels;
    LIST_FOREACH(t, head, entries)
    {
        if (t->fallback_only != use_fallbacks) {
            continue;
        }
        /* Don't select "LOSSY" tunnels, except if we are in fallback mode */
        if ((t->fallback_only && t->status >= MLVPN_AUTHOK) ||
            (t->status == MLVPN_AUTHOK))
        {
            if (wrr.len >= MAX_TUNNELS)
                fatalx("You have too much tunnels declared");
            tunnels--;
            wrr.tunnel[tunnels] = t;
            wrr.tunval[tunnels] = 0.0;
        }
    }

    return 0;
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose(uint32_t len)
{
    int i = 0;
    /* Iterate through tunnels in order of priority */
    for (i = 0; i < wrr.len; i++) {
        log_debug("wrr", "check tunnel %d/%d with %f+%u bytes used of %d total",
                i, wrr.len, wrr.tunval[i], len, wrr.tunnel[i]->bandwidth);
        /* Skip tunnels which have exhausted their bandwidth in this timeslot */
        if ((wrr.tunval[i] + len) >= wrr.tunnel[i]->bandwidth) {
            log_debug("wrr", "bandwidth exhausted!");
            continue;
        }
        wrr.tunval[i] += len;
        return wrr.tunnel[i];
    }
    log_debug("wrr", "no tunnel found for packet of len %u", len);
    /* Discard the packet in mlvpn_tuntap_generic_read() */
    return NULL;
}
