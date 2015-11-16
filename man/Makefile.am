dist_man_MANS = mlvpn.1 mlvpn.conf.5
noinst_man_MANS = mlvpn.1.ronn mlvpn.conf.5.ronn


if HAVE_RONN
mlvpn.1:
	ronn --pipe < mlvpn.1.ronn > mlvpn.1 || rm mlvpn.1 2>/dev/null

mlvpn.conf.5:
	ronn --pipe < mlvpn.conf.5.ronn > mlvpn.conf.5 || rm mlvpn.conf.5 2>/dev/null
endif
