========================
Getting started in mlvpn
========================

Introduction
============
If you haven't, read :doc:`what_is_mlvpn`.

Installation
============

Debian wheezy
-------------
If you trust me, you can use the mlvpn debian repository for Debian wheezy:

.. code-block:: sh

    # Add the mlvpn repository signature
    sudo apt-key adv --keyserver pgp.mit.edu --recv 3324C952
    echo "deb http://debian.mlvpn.fr wheezy/" >/etc/apt/sources.list.d/mlvpn.list
    sudo apt-get update
    sudo apt-get install mlvpn

.. warning:: PLEASE DO NOT USE THIS REPOSITORY YET.

Debian jessie/sid
-----------------
If you trust me, you can use the mlvpn debian repository for Debian sid:

.. code-block:: sh

    # Add the mlvpn repository signature
    sudo apt-key adv --keyserver pgp.mit.edu --recv 3324C952
    echo "deb http://debian.mlvpn.fr unstable/" >/etc/apt/sources.list.d/mlvpn.list
    sudo apt-get update
    sudo apt-get install mlvpn

OpenBSD
-------
Refer to the `README.OpenBSD <https://github.com/zehome/MLVPN/>`_
file inside the mlvpn repository for OpenBSD build instructions.

.. code-block:: sh

    # Install dependencies
    # DO NOT install libsodium from package on OpenBSD 5.6 or older
    pkg_add git autoconf automake libev libsodium
    # Adjust to your needs
    export AUTOCONF_VERSION=2.69
    export AUTOMAKE_VERSION=1.15
    export CPPFLAGS="-I/usr/local/include $CPPFLAGS"
    export LDFLAGS="-L/usr/local/lib $LDFLAGS"
    git clone https://github.com/zehome/MLVPN mlvpn
    cd mlvpn
    ./autogen.sh
    ./configure
    make
    # Install
    sudo make install
    sudo mkdir /etc/mlvpn
    sudo cp /usr/local/share/doc/mlvpn/mlvpn.conf /etc/mlvpn/
    sudo cp /usr/local/share/doc/mlvpn/mlvpn_updown_openbsd.sh /etc/mlvpn/
    sudo chown -R root /etc/mlvpn
    sudo chmod 660 /etc/mlvpn/mlvpn.conf
    sudo chmod 700 /etc/mlvpn/mlvpn_updown_openbsd.sh
    # Create a system user for mlvpn (unprivileged)
    sudo groupadd _mlvpn
    sudo useradd -c "mlvpn Daemon" -d /var/empty -s /sbin/nologin -L daemon -g _mlvpn _mlvpn

FreeBSD
-------
.. code-block:: sh

    pkg install git libev libsodium
    git clone --branch freebsd https://github.com/zehome/MLVPN mlvpn
    cd mlvpn
    make

.. note:: This port is not tested often and may break.

Install from source
-------------------
Please refer to the `README.md <https://github.com/zehome/MLVPN/>`_ file inside
the mlvpn repository for source build instructions.


Configuration
=============
mlvpn is using two configuration files for every tunnel you want to make.

mlvpn.conf
----------
`mlvpn.conf(1) <https://github.com/zehome/MLVPN/blob/ev/man/mlvpn.1.ronn>`_ is an ini-style configuration.
It's used to set the interface name, the secret-key, network configuration
of the multiple links and path to the second configration script.

Please refer the the mlvpn.conf(1) manpage for further informations.

.. note:: access the manpage using: **man mlvpn.conf**

mlvpn_updown.sh
---------------
**mlvpn_updown.sh** is a script called by mlvpn when status change occurs in mlvpn.

For example, when mlvpn is launched and a link is activated, mlvpn_updown.sh is called in order
to bring the tunnel device up and ready for communication.

