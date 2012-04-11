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
	control.c control.h \
    mlvpn.c mlvpn.h
mlvpn_LDFLAGS=-lm
CFLAGS=-Wall -Wno-strict-aliasing -Wno-format-zero-length
