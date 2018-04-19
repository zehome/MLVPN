#
# MLVPN
# (c) 2015 Laurent Coustet <ed@zehome.com>

ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = mlvpn
mlvpn_SOURCES = \
    includes.h defines.h \
    pkt.h \
    buffer.c buffer.h \
    configlib.c configlib.h \
    config.c \
    tool.c tool.h \
    privsep.c privsep_fdpass.c privsep.h \
    wrr.c \
    crypto.c crypto.h \
    log.c log.h \
    reorder.h reorder.c \
    timestamp.h timestamp.c \
    tuntap_generic.c tuntap_generic.h \
    mlvpn.c mlvpn.h

# There are better ways to do that, using a "compat" library
# and using AC_REPLACE_FUNCS.
if !HAVE_STRNVIS
mlvpn_SOURCES += vis.c vis.h
endif
if !HAVE_CLOSEFROM
mlvpn_SOURCES += closefrom.c
endif
if !HAVE_SETPROCTITLE
mlvpn_SOURCES += setproctitle.c setproctitle.h
endif
if !HAVE_STRLCAT
mlvpn_SOURCES += strlcat.c
endif
if !HAVE_STRLCPY
mlvpn_SOURCES += strlcpy.c
endif

if LINUX
mlvpn_SOURCES += tuntap_linux.c systemd.c systemd.h
endif

if BSD
mlvpn_SOURCES += tuntap_bsd.c
endif

if DARWIN
mlvpn_SOURCES += tuntap_darwin.c
endif

if ENABLE_CONTROL
mlvpn_SOURCES += control.c control.h
endif

# Always include thoses files for distribution
EXTRA_DIST = \
    closefrom.c \
    setproctitle.c setproctitle.h \
    strlcat.c \
    strlcpy.c \
    vis.c vis.h \
    tuntap_linux.c \
    tuntap_bsd.c \
    systemd.c systemd.h \
    control.c control.h

mlvpn_LDADD=-lm $(libsodium_LIBS) $(libev_LIBS)
mlvpn_CFLAGS=$(CFLAGS) $(libsodium_CFLAGS) $(libev_CFLAGS)

if HAVE_FILTERS
mlvpn_SOURCES += filters.c
mlvpn_LDADD += $(libpcap_LIBS)
mlvpn_CFLAGS += $(libpcap_CFLAGS)
endif
