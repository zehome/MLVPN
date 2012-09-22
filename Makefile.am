# MLVPN
# (c) 2012 Laurent Coustet <ed@zehome.com>
#

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES = \
    config.log config.status \
    $(srcdir)/Makefile.in \
    $(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
    $(srcdir)/build-aux/install-sh $(srcdir)/missing \
    $(srcdir)/depcomp $(srcdir)/aclocal.m4 \
    $(srcdir)/config.guess $(srcdir)/config.sub \
    $(srcdir)/mlvpn.spec

SUBDIRS = src man
dist_doc_DATA = LICENCE AUTHORS README.md examples/mlvpn.conf \
    examples/mlvpn_updown.sh examples/mlvpn.init.d default_mlvpn
