#include "includes.h"

#include <err.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/if.h>

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

    /* choosing a tunnel to send to (direct buffer copy) */
    rtun = mlvpn_rtun_choose();

    /* Not connected to anyone. read and discard packet. */
    if (! rtun)
    {
        char blackhole[DEFAULT_MTU];
        return read(tuntap->fd, blackhole, sizeof(blackhole));
    }

    /* Buffer checking / reset in case of overflow */
    sbuf = rtun->sbuf;
    if (mlvpn_cb_is_full(sbuf))
        log_warnx("tuntap", "%s buffer: overflow", rtun->name);

    /* Ask for a free buffer */
    pkt = mlvpn_pktbuffer_write(sbuf);
    ret = read(tuntap->fd, pkt->data, DEFAULT_MTU);
    if (ret < 0)
    {
        /* read error on tuntap is not recoverable. We must die. */
        fatal("tuntap", "unrecoverable read error");
    } else if (ret == 0) {
        /* End of file */
        fatalx("tuntap device closed");
    }
    pkt->len = ret;
    if (pkt->len > tuntap->maxmtu)
    {
        log_warnx("tuntap",
            "cannot send packet: too big %d/%d",
            pkt->len, tuntap->maxmtu);
        pkt->len = tuntap->maxmtu;
    }

    if (!ev_is_active(&rtun->io_write) && !mlvpn_cb_is_empty(rtun->sbuf)) {
        ev_io_start(EV_DEFAULT_UC, &rtun->io_write);
    }

    return pkt->len;
}

int
mlvpn_tuntap_write(struct tuntap_s *tuntap)
{
    int len;
    mlvpn_pkt_t *pkt;
    circular_buffer_t *buf = tuntap->sbuf;

    /* Safety checks */
    if (mlvpn_cb_is_empty(buf))
        fatalx("tuntap_write called with empty buffer");

    pkt = mlvpn_pktbuffer_read(buf);
    len = write(tuntap->fd, pkt->data, pkt->len);
    if (len < 0)
    {
        log_warn("tuntap", "%s write error", tuntap->devname);
    } else {
        if (len != pkt->len)
        {
            log_warnx("tuntap", "%s write error: %d/%d bytes sent",
               tuntap->devname, len, pkt->len);
        } else {
            log_debug("tuntap", "%s > sent %d bytes",
               tuntap->devname, len);
        }
    }

    return len;
}

int
mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    int fd;

    if ((fd = priv_open_tun(tuntap->type,
           tuntap->devname, tuntap->maxmtu)) <= 0 )
        fatalx("failed to open /dev/net/tun read/write");
    tuntap->fd = fd;
    return fd;
}

/* WARNING: called as root
 *
 * Really open the tun device.
 * returns tun file descriptor.
 *
 * Compatibility: Linux 2.4+
 */
int
root_tuntap_open(int tuntapmode, char *devname, int mtu)
{
    struct ifreq ifr;
    int fd, sockfd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        warn("failed to open /dev/net/tun");
    } else {
        memset(&ifr, 0, sizeof(ifr));
        if (tuntapmode == MLVPN_TUNTAPMODE_TAP)
            ifr.ifr_flags = IFF_TAP;
        else
            ifr.ifr_flags = IFF_TUN;

        /* We do not want kernel packet info (IFF_NO_PI) */
        ifr.ifr_flags |= IFF_NO_PI;

        /* Allocate with specified name, otherwise the kernel
         * will find a name for us. */
        if (*devname)
            strlcpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));

        /* ioctl to create the if */
        if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        {
            /* don't call fatal because we want a clean nice error for the
             * unprivilged process.
             */
            warn("open tun %s ioctl failed", devname);
            close(fd);
            return -1;
        }

        /* set tun MTU */
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            warn("socket creation failed");
        } else {
            ifr.ifr_mtu = mtu;
            if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0)
            {
                warn("unable to set tun %s mtu=%d", devname, mtu);
                close(fd);
                close(sockfd);
                return -1;
            }
            close(sockfd);
        }
    }
    /* The kernel is the only one able to "name" the if.
     * so we reread it to get the real name set by the kernel. */
    if (fd > 0) {
        strlcpy(devname, ifr.ifr_name, MLVPN_IFNAMSIZ);
    }
    return fd;
}

