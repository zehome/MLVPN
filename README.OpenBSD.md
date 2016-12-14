Building mlvpn on OpenBSD
=========================

Since OpenBSD 5.9
=================
In OpenBSD 5.9 and later, thanks yo Stuart Henderson @sthen,
you can install mlvpn like any other OpenBSD package:

```sh
pkg_add mlvpn
/etc/rc.d/mlvpn start
```

Install requirements
====================
```sh
pkg_add git autoconf automake libev libsodium
```
.. note: For OpenBSD 5.6 and older, you need to build libsodium
         from source, because the version provided is too old.

Manual build
============

```sh
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.15
export CPPFLAGS="-I/usr/local/include $CPPFLAGS"
export LDFLAGS="-L/usr/local/lib $LDFLAGS"
git clone https://github.com/zehome/MLVPN mlvpn
cd mlvpn
./autogen.sh
./configure
make
doas make install
```

Manual installation
===================
```sh
doas make install
doas mkdir /etc/mlvpn
doas cp /usr/local/share/doc/mlvpn/mlvpn.rc /etc/rc.d/mlvpn
doas cp /usr/local/share/doc/mlvpn/mlvpn.conf /etc/mlvpn/
doas cp /usr/local/share/doc/mlvpn/mlvpn_updown.sh /etc/mlvpn/
doas chown -R root:wheel /etc/mlvpn
doas chmod 660 /etc/mlvpn/mlvpn.conf
doas chmod 700 /etc/mlvpn/mlvpn_updown.sh /etc/rc.d/mlvpn

# Create a system user for mlvpn
doas groupadd _mlvpn
doas useradd -c "mlvpn Daemon" -d /var/empty -s /sbin/nologin -L daemon -g _mlvpn _mlvpn
```

Edit **/etc/mlvpn/mlvpn.conf** for your needs.

Run
===

```sh
doas mlvpn -c /etc/mlvpn/mlvpn.conf --user _mlvpn
# or using rc.d:
doas /etc/rc.d/mlvpn start
```

Don't forget you get the super easy way to configure source-routing
with mlvpn on OpenBSD. Just create your routing tables with route(8) -T
then use **bindfib** in mlvpn.conf.
