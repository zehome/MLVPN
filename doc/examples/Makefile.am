# MLVPN
# (c) 2015 Laurent Coustet <ed@zehome.com>

SUBDIRS = systemd
if INSTALL_EXAMPLES
dist_doc_DATA = mlvpn.conf \
    mlvpn_updown.sh mlvpn.init.d mlvpn.default mlvpn.rc
else
nodist_doc_DATA = mlvpn.conf mlvpn_updown.sh mlvpn.init.d mlvpn.rc
endif

mlvpn.conf: mlvpn.conf.in
mlvpn_updown.sh: mlvpn_updown.sh.in
mlvpn.init.d: mlvpn.init.d.in
mlvpn.rc: mlvpn.rc.in

TEMPLATES   = mlvpn.conf mlvpn_updown.sh mlvpn.init.d mlvpn.rc
EXTRA_DIST  = mlvpn.conf.in mlvpn_updown.sh.in mlvpn.init.d.in mlvpn.rc.in
CLEANFILES  = $(TEMPLATES)

include $(top_srcdir)/template.am
