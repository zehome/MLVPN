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
    int min_index = 0;
    int i;
    double min = wrr.tunval[0];

    for(i = 0; i < wrr.len; i++)
    {
      if ((wrr.tunval[i] < min) &&
          (wrr.tunnel[i]->quota==0 || wrr.tunnel[i]->permitted>0))
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
    mlvpn_tunnel_t *t;
    wrr.len = 0;
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
            wrr.tunnel[wrr.len] = t;
            wrr.tunval[wrr.len] = 0.0;
            wrr.len++;
        }
    }

    return 0;
}

void mlvpn_rtun_set_weight(mlvpn_tunnel_t *t, double weight)
{
  if (t->weight!=weight) {
    t->weight=weight;
    for (int i = 0; i< wrr.len; i++) {
      wrr.tunval[i] = 0.0;
    }
  }
}

mlvpn_tunnel_t *
mlvpn_rtun_wrr_choose()
{

  int idx = wrr_min_index();
  
  double total=0;
  for (int i = 0; i< wrr.len; i++) {
    total+= wrr.tunnel[i]->weight;
  }
  
  if (wrr.tunval[idx]<=0 || wrr.tunval[idx] > 10000) {
    for (int i = 0; i< wrr.len; i++) {
      if (wrr.tunnel[i]->weight) {
        wrr.tunval[i]=total / wrr.tunnel[i]->weight;
      } else {
        wrr.tunval[i]=wrr.len; // handle initial setup fairly
      }      
    }
  } else {
    wrr.tunval[idx]+=total / wrr.tunnel[idx]->weight;
  }
  
  return wrr.tunnel[idx];
}
