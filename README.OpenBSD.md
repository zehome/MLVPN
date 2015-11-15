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
.. note: For OpenBSD 5.6 and less, you need to build libsodium
         from source, because the version provided is too old.

Manual build
============

```sh
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.14
export CPPFLAGS="-I/usr/local/include $CPPFLAGS"
export LDFLAGS="-L/usr/local/lib $LDFLAGS"
git clone https://github.com/zehome/MLVPN mlvpn
cd mlvpn
./autogen.sh
./configure
make
sudo make install
```

Manual installation
===================
```sh
sudo make install
sudo mkdir /etc/mlvpn
sudo cp /usr/local/share/doc/mlvpn/mlvpn.conf /etc/mlvpn/
sudo cp /usr/local/share/doc/mlvpn/mlvpn_updown.sh /etc/mlvpn/
sudo chown -R root:wheel /etc/mlvpn
sudo chmod 660 /etc/mlvpn/mlvpn.conf
sudo chmod 700 /etc/mlvpn/mlvpn_updown.sh

# Create a system user for mlvpn
sudo groupadd _mlvpn
sudo useradd -c "mlvpn Daemon" -d /var/empty -s /sbin/nologin -L daemon -g _mlvpn _mlvpn
```

Edit **/etc/mlvpn/mlvpn.conf** for your needs.

Run
===

```sh
sudo /usr/local/sbin/mlvpn -c /etc/mlvpn/mlvpn.conf --user _mlvpn
```
