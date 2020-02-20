==================================
Building debian packages for mlvpn
==================================

Requirements
============

.. code-block:: sh

    sudo apt-get install git-buildpackage


Build the debian package using git-buildpackage
===============================================

.. code-block:: sh

    git clone https://github.com/zehome/MLVPN mlvpn
    cd mlvpn
    apt-get build-dep .
    gbp buildpackage

