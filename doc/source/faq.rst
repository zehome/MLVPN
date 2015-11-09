=========================
Fequently Asked Questions
=========================

How much mlvpn costs
====================
Free. mlvpn is licenced under the open source BSD licence.

Troubleshooting
===============

mlvpn does not launch
---------------------
Launch mlvpn manually in debug mode:
.. code-block:: sh

    mlvpn --user _mlvpn -c /etc/mlvpn.conf --debug -Dprotocol -v

Check your permissions:
.. code-block:: sh

    chmod 0600 /etc/mlvpn/mlvpn.conf
    chmod 0700 /etc/mlvpn/mlvpn_updown.sh
    chown root /etc/mlvpn/mlvpn.conf /etc/mlvpn/mlvpn_updown.sh

mlvpn does not create the tunnel interface
------------------------------------------
Follow `mlvpn does not launch`_.

