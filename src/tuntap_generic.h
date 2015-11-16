#ifndef MLVPN_TUNTAP_GENERIC_H
#define MLVPN_TUNTAP_GENERIC_H

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <ev.h>

#include "buffer.h"
#include "privsep.h"
#include "mlvpn.h"

enum tuntap_type {
    MLVPN_TUNTAPMODE_TUN,
    MLVPN_TUNTAPMODE_TAP
};

struct tuntap_s
{
    int fd;
    int maxmtu;
    char devname[MLVPN_IFNAMSIZ];
    enum tuntap_type type;
    circular_buffer_t *sbuf;
    ev_io io_read;
    ev_io io_write;
};

int mlvpn_tuntap_alloc(struct tuntap_s *tuntap);
int mlvpn_tuntap_read(struct tuntap_s *tuntap);
int mlvpn_tuntap_write(struct tuntap_s *tuntap);
int mlvpn_tuntap_generic_read(u_char *data, uint32_t len);

#endif
