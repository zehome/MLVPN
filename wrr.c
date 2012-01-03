#include "mlvpn.h"
#include "debug.h"

/* Fairly big no ? */
#define MAX_TUNNELS 128

struct mlvpn_wrr {
    mlvpn_tunnel_t *start;
    int len;
    int gcd;
    int maxw;
    int curw;
    int curi;
    mlvpn_tunnel_t *tunnels[MAX_TUNNELS];
};

static struct mlvpn_wrr wrr = {
    NULL,
    0,
    0,
    0,
    0,
    -1
};

/* (utility) highest common factor */
int gcd(int a, int b)
{
    int c;
    while ((c = a % b))
    {
        a = b;
        b = c;
    }
    return b;
}

int wrr_gcd_weight()
{
    mlvpn_tunnel_t *t = wrr.start;
    int weight, g = 0;
    while (t)
    {
        if (t->status >= MLVPN_CHAP_AUTHOK)
        {
            weight = t->weight;
            if (weight > 0)
                g = g > 0 ? gcd(weight, g) : weight;
        }
        t = t->next;
    }
    return g ? g : 1;
}
int wrr_max_weight()
{
    mlvpn_tunnel_t *t = wrr.start;
    int max = 0;
    while (t)
    {
        if (t->status >= MLVPN_CHAP_AUTHOK)
        {
            if (t->weight > max)
                max = t->weight;
        }
        t = t->next;
    }
    return max;
}

/* initialize wrr system */
int mlvpn_rtun_wrr_init(mlvpn_tunnel_t *start)
{
    mlvpn_tunnel_t *t = wrr.start;

    wrr.start = start;
    wrr.gcd = wrr_gcd_weight(wrr.start);
    wrr.curw = 0;
    wrr.curi = -1;
    wrr.maxw = wrr_max_weight(wrr.start);

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
            wrr.tunnels[wrr.len++] = t;
        }
        t = t->next;
    }
    
    return 0;
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{
    while (1)
    {
        wrr.curi = (wrr.curi + 1) % wrr.len;
        if (wrr.curi == 0)
        {
            wrr.curw -= wrr.gcd;
            if (wrr.curw <= 0)
                wrr.curw = wrr.maxw;
        }
        if (wrr.tunnels[wrr.curi]->weight >= wrr.curw)
            break;
    }

    return wrr.tunnels[wrr.curi];
}
