#include "tuntap_generic.h"
#include "strlcpy.h"
#include "debug.h"

#include <sys/uio.h>

int mlvpn_tuntap_read(struct tuntap_s *tuntap)
{
    pktbuffer_t *sbuf;
    mlvpn_tunnel_t *rtun;
    mlvpn_pkt_t *pkt;
    int ret;
    uint32_t type;
    struct iovec iov[2];

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

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = pkt->pktdata.data;
    iov[1].iov_len = DEFAULT_MTU;
    ret = readv(tuntap->fd, iov, 2);
//    ret = read(tuntap->fd, pkt->pktdata.data, DEFAULT_MTU);

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
    pkt->pktdata.len = ret - sizeof(type);

    return pkt->pktdata.len;
}

int mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    int len, datalen;
    mlvpn_pkt_t *pkt;
    pktbuffer_t *buf = tuntap->sbuf;
    uint32_t type;
    struct iovec iov[2];

    /* Safety checks */
    if (buf->len <= 0)
    {
        _FATAL("[tuntap %s] tuntap_write called with empty buffer!\n", tuntap->devname);
        return -1;
    }

    /* TODO: rewrite this to let buffer system handle this */
    pkt = &buf->pkts[0]; /* First pkt in queue */

    type = htonl(AF_INET);

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = pkt->pktdata.data;
    iov[1].iov_len = pkt->pktdata.len;

//    len = write(tuntap->fd, pkt->pktdata.data, pkt->pktdata.len);
    len = writev(tuntap->fd, iov, 2);
    datalen = len - iov[0].iov_len;
    if (len < 0)
    {
        _ERROR("[tuntap %s] write error: %s\n", tuntap->devname, strerror(errno));
    } else {
        if (datalen != pkt->pktdata.len)
        {
            _ERROR("[tuntap %s] write error: only %d/%d bytes sent.\n",
                tuntap->devname, datalen, pkt->pktdata.len);
        } else {
            _DEBUG("[tuntap %s] >> wrote %d bytes (%d pkts left).\n",
                tuntap->devname, datalen, (int)buf->len);
        }
    }

    /* freeing sent data */
    mlvpn_pop_pkt(buf);
    return datalen;
}

