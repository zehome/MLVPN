all: mlvpn

mlvpn:
	$(MAKE) -C src

adduser:
	adduser --system --home /var/spool/mlvpn --shell /bin/false --disabled-password --disabled-login mlvpn

man:
	$(MAKE) -C man all

clean:
	$(MAKE) -C src clean
	$(MAKE) -C man clean

.PHONY: all man clean mlvpn
