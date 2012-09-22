#include "tuntap_linux.h"
#include "strlcpy.h"

int mlvpn_tuntap_alloc(struct tuntap_s *tuntap)
{
    int fd;

    if ((fd = priv_open_tun(tuntap->type, tuntap->devname)) < 0 )
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
            ifr.ifr_flags = IFF_TUN;
        else
            ifr.ifr_flags = IFF_TAP;

        /* We do not want kernel packet info (IFF_NO_PI) */
        ifr.ifr_flags |= IFF_NO_PI;

        /* Allocate with specified name, otherwise the kernel
         * will find a name for us. */
        if (*devname)
            strlcpy(ifr.ifr_name, devname, IFNAMSIZ);

        /* ioctl to create the if */
        if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0)
        {
            warn("priv_open_tun failed. (Already registered ?)");
            return -1;
        }

        /* The kernel is the only one able to "name" the if.
         * so we reread it to get the real name set by the kernel. */
        strlcpy(devname, ifr.ifr_name, IFNAMSIZ);
   }
   return fd;
}

