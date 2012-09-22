#ifndef MLVPN_TUNTAP_LINUX_H
#define MLVPN_TUNTAP_LINUX_H
#include "tuntap_generic.h"

#include <err.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <linux/if_tun.h>
#include <linux/if.h>

int mlvpn_tuntap_alloc();

/* runs as root! */
int root_tuntap_open(int tuntapmode, char *devname);

#endif
