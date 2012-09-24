#include "tuntap_generic.h"
#include "strlcpy.h"
#include "debug.h"

int mlvpn_tuntap_read(struct tuntap_s *tuntap)
{
    pktbuffer_t *sbuf;
    mlvpn_tunnel_t *rtun;
    mlvpn_pkt_t *pkt;
    int ret;

    /* choosing a tunnel to send to (direct buffer copy) */
    rtun = mlvpn_rtun_choose();

    /* Not connected to anyone. read and discard packet. */
    if (! rtun)
    {
        char blackhole[DEFAULT_MTU];
        return read(tuntap->fd, blackhole, DEFAULT_MTU);
    }

    /* Buffer checking / reset in case of overflow */
    sbuf = rtun->sbuf;
    if (mlvpn_check_buffer(sbuf, 1) != 0)
        _WARNING("[tun %s] buffer overflow.\n", rtun->name);

    /* Ask for a free buffer (protected by the check just above) */
    pkt = mlvpn_get_free_pkt(sbuf);
    ret = read(tuntap->fd, pkt->pktdata.data, DEFAULT_MTU);

    if (ret < 0)
    {
        /* read error on tuntap is not recoverable. We must die. */
        _FATAL("[tuntap %s] unrecoverable read error: %s\n",
            tuntap->devname, strerror(errno));
        exit(1);
    } else if (ret == 0) {
        /* End of file */
        _FATAL("[tuntap %s] unrecoverable error (reached EOF on tuntap!)\n");
        exit(1);
    }
    pkt->pktdata.len = ret;

    return pkt->pktdata.len;
}

int mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    int len;
    mlvpn_pkt_t *pkt;
    pktbuffer_t *buf = tuntap->sbuf;

    /* Safety checks */
    if (buf->len <= 0)
    {
        _FATAL("[tuntap %s] tuntap_write called with empty buffer!\n", tuntap->devname);
        return -1;
    }

    /* TODO: rewrite this to let buffer system handle this */
    pkt = &buf->pkts[0]; /* First pkt in queue */
    len = write(tuntap->fd, pkt->pktdata.data, pkt->pktdata.len);
    if (len < 0)
    {
        _ERROR("[tuntap %s] write error: %s\n", tuntap->devname, strerror(errno));
    } else {
        if (len != pkt->pktdata.len)
        {
            _ERROR("[tuntap %s] write error: only %d/%d bytes sent.\n",
                tuntap->devname, len, pkt->pktdata.len);
        } else {
            _DEBUG("[tuntap %s] >> wrote %d bytes (%d pkts left).\n",
                tuntap->devname, len, (int)buf->len);
        }
    }

    /* freeing sent data */
    mlvpn_pop_pkt(buf);
    return len;
}

