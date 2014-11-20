#include "includes.h"

#include <err.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_tun.h>
#include <sys/uio.h>

#include "buffer.h"
#include "tuntap_generic.h"
#include "tool.h"

int
mlvpn_tuntap_read(struct tuntap_s *tuntap)
{
    circular_buffer_t *sbuf;
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
        char blackhole[DEFAULT_MTU+sizeof(type)];
        return read(tuntap->fd, blackhole, DEFAULT_MTU+sizeof(type));
    }

    /* Buffer checking / reset in case of overflow */
    sbuf = rtun->sbuf;
    if (mlvpn_cb_is_full(sbuf))
        _WARNING("[rtun %s] buffer overflow.\n", rtun->name);

    /* Ask for a free buffer */
    pkt = mlvpn_pktbuffer_write(sbuf);

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = pkt->data;
    iov[1].iov_len = DEFAULT_MTU;

    ret = readv(tuntap->fd, iov, 2);
    if (ret < 0)
    {
        /* read error on tuntap is not recoverable. We must die. */
        _FATAL("[tuntap %s] unrecoverable read error: %s\n",
               tuntap->devname, strerror(errno));
        exit(1);
    } else if (ret == 0) {
        /* End of file */
        _FATAL("[tuntap %s] unrecoverable error (reached EOF on tuntap!)\n",
               tuntap->devname);
        exit(1);
    }
    pkt->len = ret - sizeof(type);
    return pkt->len;
}

int
mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    int len, datalen;
    mlvpn_pkt_t *pkt;
    circular_buffer_t *buf = tuntap->sbuf;
    uint32_t type;
    struct iovec iov[2];

    /* Safety checks */
    if (mlvpn_cb_is_empty(buf))
    {
        _FATAL("[tuntap %s] tuntap_write called with empty buffer!\n",
               tuntap->devname);
        return -1;
    }

    pkt = mlvpn_pktbuffer_read(buf);

    type = htonl(AF_INET);

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = pkt->data;
    iov[1].iov_len = pkt->len;

    len = writev(tuntap->fd, iov, 2);
    datalen = len - iov[0].iov_len;
    if (len < 0)
    {
        _ERROR("[tuntap %s] write error: %s\n",
               tuntap->devname, strerror(errno));
    } else {
        if (datalen != pkt->len)
        {
            _ERROR("[tuntap %s] write error: only %d/%d bytes sent.\n",
                   tuntap->devname, datalen, pkt->len);
        } else {
            _DEBUG("[tuntap %s] >> wrote %d bytes.\n",
                   tuntap->devname, datalen);
        }
    }

    return datalen;
}
int
mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    char devname[8];
    int fd;
    int i;

    /* TODO: handle this by command line/config file ! */
    /* FreeBSD/OpenBSD (and others maybe) supports each tun on different device. */
    /* examples: /dev/tun0, /dev/tun2 (man 2 if_tun) */
    for (i=0; i < 32; i++)
    {
        snprintf(devname, 5, "%s%d",
                 tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun", i);
        snprintf(tuntap->devname, 10, "/dev/%s", devname);

        if ((fd = priv_open_tun(tuntap->type, tuntap->devname)) > 0 )
            break;
    }

    if (fd <= 0)
    {
        _FATAL("[tuntap] unable to open any /dev/%s0 to 32 read/write. "
               "Check permissions.\n",
               tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun");
        return fd;
    }
    tuntap->fd = fd;

    /* geting the actual tun%d inside devname
     * is required for hooks to work properly */
    strlcpy(tuntap->devname, devname, MLVPN_IFNAMSIZ-1);

    char *hook_args[3] = {tuntap->devname, "tuntap_up", NULL};
    mlvpn_hook(MLVPN_HOOK_TUNTAP, 2, hook_args);
    return tuntap->fd;
}

/* WARNING: called as root
 *
 * Really open the tun device.
 * returns tun file descriptor.
 *
 * Compatibility: BSD
 */
int
root_tuntap_open(int tuntapmode, char *devname)
{
    int fd;

    fd = open(devname, O_RDWR);
    if (fd >= 0)
    {
#ifdef HAVE_OPENBSD
        struct tuninfo tuninfo;
        tuninfo.mtu = 1500;
//        tuninfo.type = IFT_TUNNEL; /* IP */
        tuninfo.flags = IFF_POINTOPOINT;
        tuninfo.baudrate = 0;
        if (ioctl(fd, TUNSIFINFO, &tuninfo, sizeof(tuninfo)) < 0) {
            warn("ioctl(TUNSIFMODE)");
            return -1;
        }
#else
        int flags;
        flags = IFF_POINTOPOINT | IFF_MULTICAST;
        if (ioctl(fd, TUNSIFMODE, &flags) < 0) {
            warn("ioctl(TUNSIFMODE)");
            return -1;
        }

        /* TODO: change this to 1 and handle 4 bytes
         * on read for family (INET6 & so on)
         */
        flags = 0;
        if (ioctl(fd, TUNSIFHEAD, &flags) < 0)
        {
            warn("ioctl(TUNSIFHEAD)");
            return -1;
        }
#endif
    }
    return fd;
}

