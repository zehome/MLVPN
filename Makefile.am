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
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $(top_srcdir)/.version

SUBDIRS = src man
dist_doc_DATA = LICENCE AUTHORS README.md examples/mlvpn.conf \
    examples/mlvpn_updown.sh examples/mlvpn.init.d examples/default_mlvpn
