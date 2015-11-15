=========================================
MLVPN - Multi-Link Virtual Public Network
=========================================
[![Build Status](https://travis-ci.org/zehome/MLVPN.svg?branch=ev)](https://travis-ci.org/zehome/MLVPN)
[![Coverity Status](https://scan.coverity.com/projects/4405/badge.svg)](https://scan.coverity.com/projects/4405)

author: Laurent Coustet <ed arobase zehome.com>

Take a look at the official documentation on [Read The Docs](http://mlvpn.readthedocs.org/en/latest/)

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
# Debian
$ sudo apt-get install build-essential make autoconf libev-dev libsodium-dev
# OR ArchLinux
$ sudo pacman -S base-devel git libev libsodium
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

Read more about [privilege separation](http://en.wikipedia.org/wiki/Privilege_separation)

Cryptography
------------
  * Encryption: Salsa20 stream cipher
  * Authentication: Poly1305 MAC

Read more on [salsa20](http://cr.yp.to/salsa20.html) and [libsodium](http://doc.libsodium.org/).


Principle of operations
=======================
**TODO**

Compatibility
=============
Linux, OpenBSD, FreeBSD

Windows is *NOT* supported, but MLVPN runs on routers, so you can
benefit from MLVPN on *ANY* operating system of course.

Contributors
============
  * Laurent Coustet, author and maintainer
  * Philippe Pepiot, contributor (privilege separation, bugfix)
  * Ghislain Lévèque, contributor (weight round robin)
  * Fabien Dupont, contributor (bugfix)
  * Thomas Soëte, contributor (bugfix)
  * Frank Denis, contributor (documentation)
  * Nicolas Braud-Santoni, contributor (documentation)
  * Stuart Henderson, contributor (OpenBSD port/package)

LICENSE
=======
See LICENSE file.

Documentation
=============
Documentation is available on [Read The Docs](http://mlvpn.readthedocs.org/en/latest/).  
The manpage is also authored in Markdown, and converted using [ronn](http://rtomayko.github.com/ronn/).
