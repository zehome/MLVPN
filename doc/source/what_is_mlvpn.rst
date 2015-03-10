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
  * Bandwidth agregation of multiple internet connections
  * Automatic failover, without changing IP addresses or interrupting TCP connections in case of a failure
  * Encrypt and authenticate connections using libsodium_.
  * Hot configuration reload (by signaling SIGHUP)
  * Scriptable monitoring
  * Remote monitoring through UNIX socket or TCP/HTTP socket. (JSON API)

.. _libsodium: http://doc.libsodium.org/

Limitations
===========

3G/4G and ADSL
==============
mlvpn can't aggregate links too dis-similar. For example, you can't aggregate
3G link and an ADSL link properly. You can do failover scenarios however.

Aggregating links too different is difficult because mlvpn does **not** do
re-ordering of packets sent over the links. The TCP connection
inside the mlvpn tunnel will then see very dis-ordered packets and will
cap the bandwidth to the slowest's link.

Another problem is that 3G connections tends to drop packets a lot.
TCP connection will suffer a **LOT** from this and the bandwidth can't be agregated properly.


Wifi and ADSL
=============
The same applies as when using 3G and ADSL. This time, it's the network latency jitter
which will work against the agregation.

You can try it anyway, as the results may differ, based on the quality of your wifi link.
