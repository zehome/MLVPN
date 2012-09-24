#include "tuntap_bsd.h"
#include "strlcpy.h"

int mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    char devname[8];
    int fd;
    int i;

    /* TODO: handle this by command line/config file ! */
    /* FreeBSD (and others maybe) supports each tun on different device. */
    /* examples: /dev/tun0, /dev/tun2 (man 2 if_tun) */
    for (i=0; i < 32; i++)
    {
        snprintf(devname, IFNAMSIZ, "%s%d", tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun", i);
        snprintf(tuntap->devname, IFNAMSIZ-8, "/dev/%s", devname);

        if ((fd = priv_open_tun(tuntap->type, tuntap->devname)) > 0 )
            break;
    }

    if (fd < 0)
    {
        _FATAL("[tuntap] unable to open any /dev/%s0 to 32 read/write. Check permissions.\n",
            tuntap->type == MLVPN_TUNTAPMODE_TAP ? "tap" : "tun");
        return fd;
    }
    tuntap->fd = fd;

    /* geting the actual tun%d inside devname
     * is required for hooks to work properly */
    strlcpy(tuntap->devname, devname, IFNAMSIZ);


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
int root_tuntap_open(int tuntapmode, char *devname)
{
    int flags;
    int fd;

    fd = open(devname, O_RDWR);
    if (fd >= 0)
    {
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

   }
   return fd;
}

