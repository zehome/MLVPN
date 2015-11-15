#include "mlvpn.h"

extern struct mlvpn_filters_s mlvpn_filters;

mlvpn_tunnel_t *
mlvpn_filters_choose(uint32_t pktlen, const u_char *pktdata) {
    int i;
    struct pcap_pkthdr hdr;
    mlvpn_tunnel_t *tun;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = pktlen;
    hdr.len = pktlen;
    for(i = 0; i < mlvpn_filters.count; i++) {
        tun = mlvpn_filters.tun[i];
        /* Don't even consider offline interfaces */
        /* log_debug("filters", "check filter[%d] (%s)", i, tun->name); */
        if (pcap_offline_filter(&mlvpn_filters.filter[i], &hdr, pktdata) != 0) {
            if (tun->status < MLVPN_AUTHOK) {
                /* log_debug("filters", "tun %s is offline.", tun->name); */
                continue;
            }
            return tun;
        }
    }
    return NULL;
}

int
mlvpn_filters_add(const struct bpf_program *filter, mlvpn_tunnel_t *tun) {
    if (mlvpn_filters.count >= 255) {
        return -1;
    }
    memcpy(&mlvpn_filters.filter[mlvpn_filters.count], filter, sizeof(*filter));
    mlvpn_filters.tun[mlvpn_filters.count] = tun;
    mlvpn_filters.count++;
    return 0;
}
