Building mlvpn on NetBSD
========================

This port is NON WORKING at the moment.
(Some kind of tuntap issue)

Requirements
============

```shell
pkg_add pkgin
pkgin update
pkgin install mozilla-rootcerts git autoconf automake pkg-config libsodium libev
```

Build
=====
```shell
git clone https://github.com/zehome/MLVPN mlvpn
cd mlvpn
./autogen.sh
CPPFLAGS="-I/usr/pkg/include/ev" LDFLAGS="-L/usr/pkg/lib/ev" ./configure
make
```

Install
=======

```shell
make install
```


Run
===
```shell
LD_LIBRARY_PATH=/usr/pkg/include/ev mlvpn ...
```
