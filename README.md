=========================================
MLVPN - Multi-Link Virtual Public Network
=========================================

author: Laurent Coustet <ed arobase zehome.com>

Take a look at the official documentation on readthedocs.org: http://mlvpn.readthedocs.org/en/latest/

Introduction
============
MLVPN will do it's best to acheive the following tasks:

  * Bond your internet links to increase bandwidth (unlimited)
  * Secure your internet connection by actively monitoring
    your links and removing the faulty ones, without loosing
    your TCP connections.
  * Secure your internet connection to the aggregation server using
    strong cryptography.
  * Scriptable automation and monitoring.

Quick install
=============

Install debian package
----------------------
```sh
sudo apt-key adv --keyserver pgp.mit.edu --recv 3324C952
echo "deb http://debian.mlvpn.fr unstable/" >/etc/apt/sources.list.d/mlvpn.list
sudo apt-get update
sudo apt-get install mlvpn
```


Install FreeBSD port
--------------------
```sh
pkg install git libev libsodium
git clone --branch freebsd https://github.com/zehome/MLVPN mlvpn
cd mlvpn
make
```

Build from source
-----------------
```sh
$ sudo apt-get install build-essential make autoconf libev-dev libsodium-dev
$ ./autogen.sh
$ ./configure
$ make
$ make install
```

Build debian package
--------------------
```sh
$ sudo apt-get install build-essential make autoconf
$ dpkg-buildpackage -us -uc -rfakeroot
```

Dependencies
============
  - libev
  - libsodium

Security
========

Privilege separation
--------------------
MLVPN uses privilege separation to keep high privileges operations
away from the core routing stuff.

Code running as root is very minimalist and highly readable to
avoid risks as much as possible.

Read more http://en.wikipedia.org/wiki/Privilege_separation

Cryptography
------------
  * Encryption: Salsa20 stream cipher
  * Authentication: Poly1305 MAC

Read more on http://cr.yp.to/salsa20.html and http://doc.libsodium.org/.


Principle of operations
=======================
**TODO**

Compatibility
=============
Linux, OpenBSD, FreeBSD (untested)

Windows is *NOT* supported, but MLVPN runs on routers, so you can
benefit from MLVPN on *ANY* operating system of course.

Contributors
============
  * Laurent Coustet, author and maintainer
  * Philippe Pepiot, contributor (privilege separation, bugfix)
  * Ghislain Lévèque, contributor (weight round robin)
  * Fabien Dupont, contributor (bugfix)

LICENCE
=======
See LICENCE file.

Documentation
=============
Documentation is available on Read The Docs http://mlvpn.readthedocs.org/en/latest/
La page de manuel est aussi écrite en markdown. La conversion est réalisée grace a l'outil
ronn (http://rtomayko.github.com/ronn/).
