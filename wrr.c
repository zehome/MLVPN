#include "mlvpn.h"
#include "debug.h"

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

int wrr_min_index()
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
int mlvpn_rtun_wrr_init(mlvpn_tunnel_t *start)
{
    mlvpn_tunnel_t *t = start;
    wrr.len = 0;
    while (t)
    {
        if (t->status >= MLVPN_CHAP_AUTHOK)
        {
            if (wrr.len >= MAX_TUNNELS)
            {
                _ERROR("You have too much tunnels declared! (> %d)\n", wrr.len);
                return 1;
            }
            wrr.tunnel[wrr.len] = t;
            wrr.tunval[wrr.len] = 0.0;
            wrr.len++;
        }
        t = t->next;
    }
    
    return 0;
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{
    int i;
    int idx;

    if (wrr.len == 0)
        return NULL;

    idx = wrr_min_index();
    if (idx < 0)
    {
        _ERROR("Programming error: wrr_min_index < 0!\n");
        return NULL;
    }

    for(i = 0; i < wrr.len; i++)
    {
        if (wrr.tunval[i] != 0)
            wrr.tunval[i] -= 1;
    }
    wrr.tunval[idx] = (double) 100.0 / wrr.tunnel[idx]->weight;
    return wrr.tunnel[idx];
}
