#
# MLVPN
# (c) 2012 Laurent Coustet <ed@zehome.com>

AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = mlvpn
mlvpn_SOURCES = \
    pkt.h \
    buffer.c buffer.h \
    configlib.c configlib.h \
    tool.c tool.h \
    debug.c debug.h \
    ps_status.c ps_status.h \
    privsep.c privsep_fdpass.c \
    wrr.c \
    strlcpy.c \
    tuntap_generic.c \
    mlvpn.c mlvpn.h

if LINUX
mlvpn_SOURCES += tuntap_linux.c tuntap_linux.h
endif

if BSD
mlvpn_SOURCES += tuntap_bsd.c tuntap_bsd.h
endif

if MLVPN_CONTROL
mlvpn_SOURCES += control.c
endif

mlvpn_LDFLAGS=-lm
CFLAGS=-g -Wall -Wno-strict-aliasing -Wno-format-zero-length
