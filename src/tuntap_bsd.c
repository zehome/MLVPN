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
    ssize_t ret;
    u_char data[DEFAULT_MTU];
    struct iovec iov[2];
    uint32_t type;

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = &data;
    iov[1].iov_len = DEFAULT_MTU;
    ret = readv(tuntap->fd, iov, 2);
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            /* read error on tuntap is not recoverable. We must die. */
            fatal("tuntap", "unrecoverable read error");
        } else {
            /* false reading from libev read would block, we can't read */
            return 0;
        }
    } else if (ret == 0) { /* End of file */
        fatalx("tuntap device closed");
    } else if (ret > tuntap->maxmtu)  {
        log_warnx("tuntap",
            "cannot send packet: too big %d/%d. truncating",
            (uint32_t)ret, tuntap->maxmtu);
        ret = tuntap->maxmtu;
    }
    return mlvpn_tuntap_generic_read(data, ret);
}

int
mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    ssize_t ret;
    int datalen = 0;
    mlvpn_pkt_t *pkt;
    circular_buffer_t *buf = tuntap->sbuf;
    uint32_t type;
    struct iovec iov[2];

    if (mlvpn_cb_is_empty(buf))
        fatalx("tuntap_write called with empty buffer");

    pkt = mlvpn_pktbuffer_read(buf);

    type = htonl(AF_INET);

    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = pkt->data;
    iov[1].iov_len = pkt->len;

    ret = writev(tuntap->fd, iov, 2);
    if (ret < 0) {
        log_warn("tuntap", "%s write error", tuntap->devname);
    } else {
        datalen = ret - iov[0].iov_len;
        if (datalen != pkt->len) {
            log_warnx("tuntap", "%s write error: only %d/%d bytes sent",
               tuntap->devname, datalen, pkt->len);
        } else {
            log_debug("tuntap", "%s > sent %d bytes",
               tuntap->devname, datalen);
        }
    }
    return datalen;
}
int
mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    char devname[16];
    int fd;
    int i;

    /* TODO: handle this by command line/config file ! */
    /* FreeBSD/OpenBSD (and others maybe) supports each tun on different device. */
    /* examples: /dev/tun0, /dev/tun2 (man 2 if_tun) */
    if (strcmp(tuntap->devname, "tun") == 0) {
        for (i=0; i < 32; i++)
        {
            snprintf(devname, 16, "%s%d",
                     tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun", i);
            snprintf(tuntap->devname, sizeof(tuntap->devname), "/dev/%s", devname);

            if ((fd = priv_open_tun(tuntap->type,
                    tuntap->devname, tuntap->maxmtu)) > 0 )
                break;
        }
        if (fd <= 0)
        {
            log_warnx("tuntap",
                "unable to open any /dev/%s0 to 32 read/write. "
                "please check permissions. (or try MAKEDEV ?)",
                tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun");
            return fd;
        } else {
            strlcpy(tuntap->devname, devname, sizeof(tuntap->devname));
        }
    } else {
        /* tunXX specified, try to open this one. */
        snprintf(devname, 16, "/dev/%s", tuntap->devname);
        fd = priv_open_tun(tuntap->type, devname, tuntap->maxmtu);
        if (fd <= 0) {
            log_warnx("tuntap", "unable to open /dev/%s read/write. MAKEDEV ?", tuntap->devname);
            return fd;
        }
    }
    tuntap->fd = fd;
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
root_tuntap_open(int tuntapmode, char *devname, int mtu)
{
    int fd;

    fd = open(devname, O_RDWR);
    if (fd >= 0)
    {
#ifdef HAVE_OPENBSD
        struct tuninfo tuninfo;
        tuninfo.mtu = mtu;
        tuninfo.flags = IFF_POINTOPOINT;
        tuninfo.baudrate = 0;
        if (ioctl(fd, TUNSIFINFO, &tuninfo, sizeof(tuninfo)) < 0) {
            warn("ioctl(TUNSIFMODE)");
            close(fd);
            return -1;
        }
#else
        int flags;
        flags = IFF_POINTOPOINT | IFF_MULTICAST;
        if (ioctl(fd, TUNSIFMODE, &flags) < 0) {
            warn("ioctl(TUNSIFMODE)");
            close(fd);
            return -1;
        }

        flags = 1;
        if (ioctl(fd, TUNSIFHEAD, &flags) < 0)
        {
            warn("ioctl(TUNSIFHEAD)");
            close(fd);
            return -1;
        }
        /* TODO change MTU on FreeBSD */
#endif
    }
    return fd;
}

