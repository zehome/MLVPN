#include "mlvpn.h"
#include "debug.h"

struct mlvpn_wrr {
    mlvpn_tunnel_t *start;
    int len;
    int gcd;
    int maxw;
    int curw;
    int curi;
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

int wrr_len(mlvpn_tunnel_t *start)
{
    mlvpn_tunnel_t *t = start;
    int len = 0;
    while (t)
    {
        if (t->status >= MLVPN_CHAP_AUTHOK)
            len++;
        t = t->next;
    }
    return len;
}

/* initialize wrr system */
int mlvpn_rtun_wrr_init(mlvpn_tunnel_t *start)
{
    wrr.start = start;
    wrr.gcd = wrr_gcd_weight(wrr.start);
    wrr.curw = 0;
    wrr.curi = -1;
    wrr.len = wrr_len(wrr.start);
    wrr.maxw = wrr_max_weight(wrr.start);
    return 0;
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{
    mlvpn_tunnel_t *t = wrr.start;

    while (t)
    {
        if (t->status >= MLVPN_CHAP_AUTHOK)
        {
            wrr.curi = (wrr.curi + 1) % wrr.len;
            if (wrr.curi == 0)
            {
                wrr.curw -= wrr.gcd;
                if (wrr.curw <= 0)
                    wrr.curw = wrr.maxw;
            }
            if (t->weight >= wrr.curw)
                goto out;
        }
        t = t->next;
    }
out:
    return t;
}
