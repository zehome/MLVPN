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
`mlvpn.conf(5) <https://github.com/zehome/MLVPN/blob/master/man/mlvpn.conf.5.ronn>`_ is an ini-style configuration.
It's used to set the interface name, the secret-key, network configuration
of the multiple links and path to the second configration script.

Please refer the the mlvpn.conf(5) manpage for further informations.

.. note:: access the manpage using: **man mlvpn.conf**

mlvpn_updown.sh
---------------
**mlvpn_updown.sh** is a script called by mlvpn when status change occurs in mlvpn.

For example, when mlvpn is launched and a link is activated, mlvpn_updown.sh is called in order
to bring the tunnel device up and ready for communication.

Checking mlvpn status using ps
==============================
You can check what mlvpn is doing at any time
by using standard unix command **ps**.

mlvpn spawns two process. One privileged running as root with [priv] in it's name.

The other running as the user you have selected with running mlvpn --user.


Example:

.. code-block:: none

    root     30222 30221  0 23:17 pts/8    00:00:00 mlvpn: adsl3g [priv]
    ed       30223 30222  0 23:17 pts/8    00:00:00 mlvpn: adsl3g !3g @adsl

This output means tunnel 3g is down, and adsl is up.

Tunnel prefix reference
-----------------------
    * '!' means down
    * '@' means up & running
    * '~' means up but lossy (above the configured threshold)

Hot reloading mlvpn configuration
=================================
mlvpn supports hot configuration reloading. You can reload the configuration
by sending the **SIGHUP** signal to any process.

.. code-block:: sh
    
    kill -HUP $(pidof mlvpn)
    # or pkill -HUP mlvpn


.. warning:: Hot reloading the configuration forces every established link
    to be disconnected and reconnected.
