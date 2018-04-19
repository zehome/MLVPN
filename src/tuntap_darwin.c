#include "includes.h"

#include <err.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if_utun.h>

#include "buffer.h"
#include "tuntap_generic.h"
#include "tool.h"

int
mlvpn_tuntap_read(struct tuntap_s *tuntap)
{
    ssize_t ret;
    u_char data[DEFAULT_MTU];
    ret = read(tuntap->fd, &data, DEFAULT_MTU);
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
            "cannot send packet: too big %zd/%d. truncating",
            ret, tuntap->maxmtu);
        ret = tuntap->maxmtu;
    }
    return mlvpn_tuntap_generic_read(data, ret);
}

int
mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    ssize_t ret;
    mlvpn_pkt_t *pkt;
    circular_buffer_t *buf = tuntap->sbuf;

    /* Safety checks */
    if (mlvpn_cb_is_empty(buf))
        fatalx("tuntap_write called with empty buffer");

    pkt = mlvpn_pktbuffer_read(buf);
    ret = write(tuntap->fd, pkt->data, pkt->len);
    if (ret < 0)
    {
        log_warn("tuntap", "%s write error", tuntap->devname);
    } else {
        if (ret != pkt->len)
        {
            log_warnx("tuntap", "%s write error: %zd/%d bytes sent",
               tuntap->devname, ret, pkt->len);
        } else {
            log_debug("tuntap", "%s > sent %zd bytes",
               tuntap->devname, ret);
        }
    }
    return ret;
}

int
mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    char devname[8];
    int fd;
    int i;

    for (i=0; i < 32; i++)
    {
        snprintf(devname, 5, "%s%d",
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
            "please check permissions.",
            tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun");
        return fd;
    }
    tuntap->fd = fd;

    strlcpy(tuntap->devname, devname, sizeof(tuntap->devname));
    return tuntap->fd;
}

/* WARNING: called as root
 *
 * Really open the tun device.
 * returns tun file descriptor.
 *
 * Compatibility: Darwin
 */
int
root_tuntap_open(int tuntapmode, char *devname, int mtu)
{
    int fd;

    fd = open(devname, O_RDWR);
    return fd;
}
