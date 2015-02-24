# MLVPN
# (c) 2015 Laurent Coustet <ed@zehome.com>

TEMPLATES =

## systemd service file
if HAVE_SYSTEMDSYSTEMUNITDIR
systemdsystemunit_DATA = mlvpn.service mlvpn@.service
TEMPLATES += $(systemdsystemunit_DATA)
endif

if HAVE_SYSTEMDSYSTEMGENERATORDIR
systemdsystemgenerator_SCRIPTS = mlvpn-generator
TEMPLATES += $(systemdsystemgenerator_SCRIPTS)
endif

if HAVE_SYSTEMDTMPFILESDIR
systemdtmpfiles_DATA = mlvpn.conf
TEMPLATES += $(systemdtmpfiles_DATA)
endif

EXTRA_DIST = mlvpn.service.in mlvpn@.service.in mlvpn-generator.in mlvpn.conf.in

mlvpn.service: mlvpn.service.in
mlvpn@.service: mlvpn@.service.in
mlvpn-generator: mlvpn-generator.in
mlvpn.conf: mlvpn.conf.in

CLEANFILES  = $(TEMPLATES)

include $(top_srcdir)/template.am
