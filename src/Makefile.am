#
# MLVPN
# (c) 2015 Laurent Coustet <ed@zehome.com>

ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = mlvpn
mlvpn_SOURCES = \
    pkt.h \
    buffer.c buffer.h \
    configlib.c configlib.h \
    config.c \
    tool.c tool.h \
    privsep.c privsep_fdpass.c \
    wrr.c \
    crypto.c \
    log.c \
    mlvpn.c mlvpn.h
mlvpn_SOURCES += \
    closefrom.c \
    setproctitle.c \
    strlcat.c \
    strlcpy.c \
    vis.c vis.h

if LINUX
mlvpn_SOURCES += tuntap_linux.c systemd.c systemd.h
endif

if BSD
mlvpn_SOURCES += tuntap_bsd.c
endif

if ENABLE_CONTROL
mlvpn_SOURCES += control.c
endif

mlvpn_LDFLAGS=-lm $(libsodium_LIBS) $(libev_LIBS)
mlvpn_CFLAGS=$(CFLAGS) $(libsodium_CFLAGS) $(libev_CFLAGS)
