#ifndef MLVPN_TUNTAP_BSD_H
#define MLVPN_TUNTAP_BSD_H
#include "tuntap_generic.h"

#include <err.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_tun.h>

#ifndef IFNAMSIZ
 #define IFNAMSIZ 64
#endif

int mlvpn_tuntap_alloc(struct tuntap_s *tuntap);

/* runs as root! */
int root_tuntap_open(int tuntapmode, char *devname);

#endif
