=============
What is mlvpn
=============

mlvpn is a piece of software, similar to OpenVPN_, which can create a network
tunnel between two computers.

mlvpn encapsulates network packets, using UDP and send them encrypted over the
internet to another location.

The primary use of mlvpn is to create bonded/aggregated_ network links in order to
benefit from the bandwidth of multiple links.

Still, mlvpn can be used as a regular secure tunnel daemon, capable of handling failover
scenarios.

.. _OpenVPN: https://www.openvpn.net/
.. _aggregated: http://en.wikipedia.org/wiki/Link_aggregation

Features
========
  * Bandwidth aggregation of multiple internet connections
  * Automatic failover, without changing IP addresses or interrupting TCP connections in case of a failure
  * Encrypt and authenticate connections using libsodium_.
  * Hot configuration reload (by signaling SIGHUP)
  * Scriptable monitoring
  * Remote monitoring through UNIX socket or TCP/HTTP socket. (JSON API)

.. _libsodium: http://doc.libsodium.org/

Limitations
===========

Non equivalent links (3G/4G and *DSL or WIFI and *DSL)
======================================================
mlvpn can aggregate very different links if reordering is enabled.

If you have a high latency 3G/4G link and a DSL connection, then
adjust reorder_buffer_size to a reasonable value to get good performance.

Note that the created aggregated link will have the WORST latency of all the links. ie: the 3G/4G link.

Re-ordering is important because packets are not sent at the same speed
on every path. Packets would come of order which confuses a LOT TCP.
Without re-ordering enabled, expect to have the bandwidth of the slowest link.

