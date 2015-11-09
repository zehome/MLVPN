Filtering 
=========
The filtering system in mlvpn can be used when you use mlvpn
in an aggregated scenario.

Some protocols will suffer a lot from packets received out-of-order, or from packet loss,
like VoIP systems.

In order to avoid that problem, mlvpn includes a system called "filters".

In **mlvpn.conf**, the **[filters]** section defines static paths for
the matched expression.

Expressions are standard BPF_ expressions. (like in tcpdump or any other libpcap program)

Filters are order sensitive.

.. _BPF: https://fr.wikipedia.org/wiki/BSD_Packet_Filter


ADSL and SDSL with reordering enabled and VoIP
==============================================

In such a scenario, we want to aggregate the traffic from every protocol
except for SIP UDP port 5060.

mlvpn.conf
----------

.. code-block:: ini

    [general]
    # This configuration is not complete, please refer to the example
    # configuration file provided with your distribution package.
    #
    reorder_buffer_size 64
    loss_tolerence = 50

    [filters]
    sdsl = udp port 5060
    adsl = udp port 5060

    [sdsl]
    remotehost = sdslgw.mlvpn.fr
    remoteport = 5080

    [adsl]
    remotehost = adslgw.mlvpn.fr
    remoteport = 5081


Explanation
-----------
This configuration, when all links are up forces packets matching the 
"udp port 5060" BPF expression to be sent only on the *sdsl* link.

If the **sdsl** link is not available, then the second matching interface
will be choosen.

Filters are EXCLUSIVE FIRST MATCH. That means if a packet matches an expression,
and the interface is ready to receive data, filtering STOPS and the packet is sent.

Order is VERY important is that situation in order to let you choose the prefered path.
