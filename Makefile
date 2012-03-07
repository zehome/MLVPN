all: mlvpn

mlvpn:
	$(MAKE) -C src

adduser:
	adduser --system --home /var/spool/mlvpn --shell /bin/false --disabled-password --disabled-login mlvpn

man:
	$(MAKE) -C man all

install:
	echo "Todo!"

dist:
	git archive --format tar.gz --prefix "mlvpn-1.0/" --output "../mlvpn_1.0.orig.tar.gz" master

clean:
	$(MAKE) -C src clean
	$(MAKE) -C man clean

.PHONY: all man clean mlvpn
