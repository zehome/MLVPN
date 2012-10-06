
#include "config.h"

#include <err.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/if.h>

#include "tuntap_generic.h"
#include "strlcpy.h"


int mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    int fd;

    if ((fd = priv_open_tun(tuntap->type, tuntap->devname)) <= 0 )
    {
        _FATAL("[tuntap %s] unable to open /dev/net/tun read/write. Check permissions.\n",
            tuntap->devname);
        return fd;
    }
    tuntap->fd = fd;

    char *hook_args[3] = {tuntap->devname, "tuntap_up", NULL};
    mlvpn_hook(MLVPN_HOOK_TUNTAP, 2, hook_args);
    return fd;
}

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


/* WARNING: called as root
 *
 * Really open the tun device.
 * returns tun file descriptor.
 *
 * Compatibility: Linux 2.4+
 */
int root_tuntap_open(int tuntapmode, char *devname)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd >= 0)
    {
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
            strlcpy(ifr.ifr_name, devname, MLVPN_IFNAMSIZ-1);

        /* ioctl to create the if */
        if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
        {
            warn("priv_open_tun failed. (Already registered ?)");
            return -1;
        }

        /* The kernel is the only one able to "name" the if.
         * so we reread it to get the real name set by the kernel. */
        strlcpy(devname, ifr.ifr_name, MLVPN_IFNAMSIZ-1);
   }
   return fd;
}

