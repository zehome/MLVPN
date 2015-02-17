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

SUBDIRS = src man
dist_doc_DATA = AUTHORS README.md examples/mlvpn.conf \
    examples/mlvpn_updown.sh examples/mlvpn.init.d examples/default_mlvpn \
    examples/mlvpn_updown_openbsd.sh

## systemd service file
if HAVE_SYSTEMDSYSTEMUNITDIR
systemdsystemunit_DATA = examples/systemd/mlvpn.service examples/systemd/mlvpn@.service
endif
if HAVE_SYSTEMDSYSTEMGENERATORDIR
systemdsystemgenerator_DATA = examples/systemd/mlvpn-generator
endif
if HAVE_SYSTEMDTMPFILESDIR
systemdtmpfiles_DATA = examples/systemd/mlvpn.conf
endif

EXTRA_dist = examples/systemd/mlvpn.service examples/systemd/mlvpn@.service examples/systemd/mlvpn.conf examples/systemd/mlvpn-generator  mlvpn.service
