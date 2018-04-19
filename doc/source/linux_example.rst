=======================================================
Linux with two ADSL uplinks for agregation and failover
=======================================================

Introduction
============
This short guide will try to help you configure linux for
policyrouting in order to automatically use the two
adsl links at the same time.

Example case
============
.. code-block:: none

                                                            128.128.128.128
                                                           +---------------+
                                              +----------->| Fast internet |--> OUT
                                              |            +---------------+
                                      mlvpn0  |
                                 +------------+-+
                       +-------->| MLVPN server |<--------+
                       |         +--------------+         |
                       |             ^      ^             |
                       |             | T  A |             |
                 +-----+------+      | U  G |      +------+-----+
                 |   ADSL 1   |      | N  G |      |   ADSL 2   |
                 +------------+      | /  R |      +------------+
                 192.168.1.1/24      | T  E |      192.168.2.1/24
                       ^             | A  G |             ^
                       |             | P  A |             |
                       |             |    T |             |
                       |             |    E |             |
            internet 1 |             |    D |             | internet 2
                       |             v      v             |
                       |         +---+------+---+         |
                       +---------| MLVPN client |---------+
                                 +--------------+
                            mlvpn0 ; eth0: 192.168.0.1
                                        ^
        +------+                        |
        | LAN  |------------------------+
        +------+
     192.168.0.0/24


In this setup we have multiple machines:

  * MLVPN server which has a fast internet connection (100Mbps)

    - Public IP Address: 128.128.128.128/32

  * ADSL 1 router LOCAL IP address 192.168.1.1/24
  * ADSL 2 router LOCAL IP address 192.168.2.1/24
  * Local AREA network (where your standard "clients" are) on 192.168.0.0/24
  * And finally our MLVPN client router:

    - Private IP address 192.168.1.2/24 to join ADSL1
    - Private IP address 192.168.2.2/24 to join ADSL2
    - Private IP address 192.168.0.1/24 for LAN clients

Yeah seems a bit complicated, but that's not that hard after all, we just have 4 routers.

Testing the basic configuration
===============================
At this time from "MLVPN client" you should be able to ping 192.168.2.1 and
192.168.1.1.

You should be able to access the internet using both links.

You can test it using standard routing.

Before we do anything: (Note: you may require installing iproute2)

.. code-block:: sh

    root@mlvpnclient:~# ip route show
    default via 192.168.1.1 dev eth0
    192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.1
    192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.2
    192.168.2.0/24 dev eth0  proto kernel  scope link  src 192.168.2.2

This routing table means every packet to the internet will go thru 192.168.1.1.
We can test it:

.. code-block:: sh

    root@mlvpnclient:~# ping -n -c2 -I192.168.1.2 ping.ovh.net
    PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
    64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=42.1 ms
    64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=41.7 ms

Ok I started to use "-I192.168.1.2" here. That's not mandatory in this
example, but this will become handy later.

"-I" means we tell the ping command to use 192.168.1.2 as source address of the packets
we are sending to ping.ovh.net.

Now, we know our ADSL1 link is working properly.

Testing the second link will need us to modify the routing table.

.. code-block:: sh

    root@mlvpnclient:~# ip route add 213.186.33.13 via 192.168.2.1
    root@mlvpnclient:~# ip route show
    default via 192.168.1.1 dev eth0
    213.186.33.13 via 192.168.2.2 dev eth0
    192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.1
    192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.2
    192.168.2.0/24 dev eth0  proto kernel  scope link  src 192.168.2.2


Notice the new 213.186.33.13 (ping.ovh.net) added to the routing table.

Again, we can test the link:

.. code-block:: sh

    root@mlvpnclient:~# ping -n -c2 -I192.168.2.2 ping.ovh.net
    PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
    64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=62.4 ms
    64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=61.1 ms

Noticed we changed the source address.

Everything is fine, let's cleanup the routing table:

.. code-block:: sh

    root@mlvpnclient:~# ip route del 213.186.33.13


Configuring the source routing
==============================
Concepts
--------
Now you have two internet access, one fast internet access on the server side,
but you have only one IP address on this server... How can you use your multiple
ADSL links at the same time ?

That's fairly simple, but a bit complicated to setup. It's called "source routing".

Source routing means the kernel will take the decision to route a packet not only
based on it's destination (like we have done just before), but also from where it came.

In our example, we want a packet coming from 192.168.2.2 to go thru ADSL 2 and a packet
from 192.168.1.2 to go thru ADSL1. Simple yah?

Let's configure it
------------------
First, you need to create multiple routing tables in the kernel.

That's better to name them, so yo do it by modifing **/etc/iproute2/rt_tables**.

.. code-block:: sh

    root@mlvpnclient:~# echo 101 adsl1 >> /etc/iproute2/rt_tables
    root@mlvpnclient:~# echo 102 adsl2 >> /etc/iproute2/rt_tables


Your configuration file should now look like this

.. code-block:: sh

    root@mlvpnclient:~# cat /etc/iproute2/rt_tables
    #
    # reserved values
    #
    255	local
    254	main
    253	default
    0	unspec
    #
    # local
    #
    #1	inr.ruhep
    101 adsl1
    102 adsl2

We have "named" two new routing tables, but we did not create them.
/etc/iproute2/rt_tables file is optional.

We must add some routes to each table to activate them.

.. code-block:: sh

    # Inserting routes in the adsl1 table
    ip route add 192.168.1.0/24 dev eth0 scope link table adsl1
    ip route add default via 192.168.1.1 dev eth0 table adsl1

    # Inserting routes in the adsl2 table
    ip route add 192.168.2.0/24 dev eth0 scope link table adsl2
    ip route add default via 192.168.2.1 dev eth0 table adsl2

    # ip rule is the source routing magic. This will redirect
    # packets coming from source "X" to table "adsl1", "adsl2" or "default".
    ip rule add from 192.168.1.0/24 table adsl1
    ip rule add from 192.168.2.0/24 table adsl2


I've stripped root@machine for you, so you can copy paste ;-)

Testing
-------
First, show me your configuration! The first thing you should always do is
displaying ip rules. (Which routing table will be used when ?)

(Please note rules are applied in order from 0 to 32767)

.. code-block:: sh

    root@mlvpnclient:~# ip rule list
      0:      from all lookup local
      32764:  from 192.168.1.0/24 lookup adsl1
      32765:  from 192.168.2.0/24 lookup adsl2
      32766:  from all lookup main
      32767:  from all lookup default


Then the routing tables:

.. code-block:: sh

    root@mlvpnclient:~# ip route show table adsl1
      192.168.1.0/24 dev eth0  scope link
      default via 192.168.1.1 dev eth0
    root@mlvpnclient:~# ip route show table adsl2
      192.168.2.0/24 dev eth0  scope link
      default via 192.168.2.1 dev eth0
    root@mlvpnclient:~# ip route show table main
      default via 192.168.1.1 dev eth0
      213.186.33.13 via 192.168.2.2 dev eth0
      192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.1
      192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.2
      192.168.2.0/24 dev eth0  proto kernel  scope link  src 192.168.2.2


Ping test

.. code-block:: sh

    root@mlvpnclient:~# ping -c2 -n -I192.168.1.1 ping.ovh.net
    PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
    64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=40.6 ms
    64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=41.5 ms

    root@mlvpnclient:~# ping -c2 -n -I192.168.2.1 ping.ovh.net
    PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
    64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=62.0 ms
    64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=64.1 ms

Hey that's working fine !

Scripting for startup ?
-----------------------
On Debian GNU/Linux that's pretty easy, just copy this script to
/usr/local/sbin/source_routing:

.. code-block:: sh

    #!/bin/sh

    # Inserting routes in the adsl1 table
    /sbin/ip route add 192.168.1.0/24 dev eth0 scope link table adsl1
    /sbin/ip route add default via 192.168.1.1 dev eth0 table adsl1

    # Inserting routes in the adsl2 table
    /sbin/ip route add 192.168.2.0/24 dev eth0 scope link table adsl2
    /sbin/ip route add default via 192.168.2.1 dev eth0 table adsl2

    # ip rule is the source routing magic. This will redirect
    # packets coming from source "X" to table "adsl1", "adsl2" or "default".
    /sbin/ip rule add from 192.168.1.0/24 table adsl1
    /sbin/ip rule add from 192.168.2.0/24 table adsl2


Verify permissions: **chmod +x /usr/local/sbin/source_routing**

You can use post-up scripts of /etc/network/interfaces to run this script.

/etc/network/interfaces

.. code-block:: none

    auto eth0
    iface eth0 inet static
        address 192.168.0.1
        netmask 255.255.255.0
        post-up /usr/local/sbin/source_routing

    auto eth0:adsl1
    iface eth0:adsl1 inet static
        address 192.168.1.2
        netmask 255.255.255.0
        gateway 192.168.1.1

    auto eth0:adsl2
    iface eth0:adsl2 inet static
        address 192.168.2.2
        netmask 255.255.255.0

Don't forget to execute the script once by hand or thru **service networking restart**.

Configuring MLVPN
=================
MLVPN have two configuration files on each side.

Client side
-----------

mlvpn0.conf
~~~~~~~~~~~
I've made the configuration file as small as possible to have a good overview.

Take a look at example config files for more details. (**man mlvpn.conf** can be usefull)

`/etc/mlvpn/mlvpn0.conf`

.. code-block:: ini

    [general]
    statuscommand = "/etc/mlvpn/mlvpn0_updown.sh"
    tuntap = "tun"
    mode = "client"
    interface_name = "mlvpn0"
    timeout = 30
    password = "you have not changed me yet?"
    reorder_buffer_size = 64
    loss_tolerence = 50

    [filters]

    [adsl1]
    bindhost = "192.168.1.2"
    remotehost = "128.128.128.128"
    remoteport = 5080

    [adsl2]
    bindhost = "192.168.2.2"
    remotehost = "128.128.128.128"
    remoteport = 5081


mlvpn0_updown.sh
~~~~~~~~~~~~~~~~~
This file *MUST* be chmod 700 (rwx------) owned by *root*.

.. code-block:: sh

    chmod 700 /etc/mlvpn/mlvpn0_updown.sh; chown root:root /etc/mlvpn/mlvpn0_updown.sh


Again I stripped the script to the minimum.

`/etc/mlvpn/mlvpn0_updown.sh`

.. code-block:: sh

    #!/bin/bash

    error=0; trap "error=$((error|1))" ERR

    tuntap_intf="$1"
    newstatus="$2"
    rtun="$3"

    [ -z "$newstatus" ] && exit 1

    (
    if [ "$newstatus" = "tuntap_up" ]; then
        echo "$tuntap_intf setup"
        /sbin/ip link set dev $tuntap_intf mtu 1400 up
        /sbin/route add proof.ovh.net dev $tuntap_intf
    elif [ "$newstatus" = "tuntap_down" ]; then
        echo "$tuntap_intf shutdown"
        /sbin/route del proof.ovh.net dev $tuntap_intf
    elif [ "$newstatus" = "rtun_up" ]; then
        echo "rtun [${rtun}] is up"
    elif [ "$newstatus" = "rtun_down" ]; then
        echo "rtun [${rtun}] is down"
    fi
    ) >> /var/log/mlvpn_commands.log 2>&1

    exit $errors

Again ensure permissions are correct or mlvpn will *NOT* execute the script.


Server side
-----------
mlvpn0.conf
~~~~~~~~~~~

.. code-block:: ini

    [general]
    statuscommand = "/etc/mlvpn/mlvpn0_updown.sh"
    tuntap = "tun"
    mode = "server"
    interface_name = "mlvpn0"
    timeout = 30
    password = "pleasechangeme!"
    reorder_buffer_size = 64
    loss_tolerence = 50

    [filters]

    [adsl1]
    bindport = 5080

    [adsl2]
    bindport = 5081


mlvpn0_updown.sh
~~~~~~~~~~~~~~~~
.. code-block:: sh

    #!/bin/bash

    error=0; trap "error=$((error|1))" ERR
    tuntap_intf="$1"
    newstatus="$2"
    rtun="$3"
    [ -z "$newstatus" ] && exit 1
    (
    if [ "$newstatus" = "tuntap_up" ]; then
        echo "$tuntap_intf setup"
        /sbin/ip link set dev $tuntap_intf mtu 1400 up
        # NAT thru our server (eth0 is our output interface on the server)
        # LAN 192.168.0.0/24 from "client"
        /sbin/ip route add 192.168.0.0/24 dev $tuntap_intf
        /sbin/iptables -t nat -A POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE
    elif [ "$newstatus" = "tuntap_down" ]; then
        /sbin/iptables -t nat -D POSTROUTING -o eth0 -s 192.168.0.0/24 -j MASQUERADE
    fi
    ) >> /var/log/mlvpn_commands.log 2>&1
    exit $errors


Testing
=======
Double check permissions of /etc/mlvpn/\*.sh (chmod 700 owned by root)

Don't forget to accept UDP 5080 and 5081 on your firewall, server side.

.. code-block:: sh

    root@server:~ # iptables -I INPUT -i eth0 -p udp --dport 5080 -s [ADSL1_PUBLICIP] -j ACCEPT
    root@server:~ # iptables -I INPUT -i eth0 -p udp --dport 5081 -s [ADSL2_PUBLICIP] -j ACCEPT

Start mlvpn on server side manually

.. code-block:: sh

    root@server:~ # mlvpn --user mlvpn -c /etc/mlvpn/mlvpn0.conf

Start mlvpn on client side manually

.. code-block:: sh

    root@client:~ # mlvpn --user mlvpn -c /etc/mlvpn/mlvpn0.conf

Check logfiles on client

.. code-block:: sh

    root@client:~ # cat /var/log/mlvpn_commands.log
    mlvpn0 setup
    rtun [adsl1] is up
    rtun [adsl2] is up

Seems good. Let's test the ICMP echo reply. (ping)

.. code-block:: sh

    # Testing connectivity to the internet
    root@client:~ # ping -n -c1 -I192.168.0.1 proof.ovh.net
    # Download speed testing
    root@client:~ # wget -4 -O/dev/null http://proof.ovh.net/files/10Gio.dat

