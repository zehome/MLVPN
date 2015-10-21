# MLVPN
# (c) 2015 Laurent Coustet <ed@zehome.com>
#

ACLOCAL_AMFLAGS = -I m4
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

SUBDIRS = src man doc
dist_doc_DATA = AUTHORS README.md README.OpenBSD.md README.NetBSD.md README.debug.md README.Debian

release:
	git describe --tags >.tarball-version
	./autogen.sh
	make dist
