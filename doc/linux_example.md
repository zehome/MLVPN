=======================================================
Configuring Linux routing for use with multi link MLVPN
=======================================================

Introduction
============
This short guide will try to help you configure linux for
multi-link routing.

MLVPN will need to have a way to communicate from one end
to the other using multiple links in order to aggregate them.

Example case
============
```
                                                            128.128.128.128
											 			   +---------------+
                                              +----------->| Fast internet |--> OUT
                                              |            +---------------+
                           mlvpn0: 10.42.42.1 |
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
                        mlvpn0: 10.42.42.2 eth0: 192.168.0.1
                                        ^
        +------+                        |
        | LAN  |------------------------+
        +------+
     192.168.0.0/24 
```

In this setup we have multiple machines:
  * MLVPN server which has a fast internet connection (100Mbps).
    - Public IP Address: 128.128.128.128/32
    - Private mlvpn IP address: 10.42.42.1/30
  * ADSL 1 router LOCAL IP address 192.168.1.1/24
  * ADSL 2 router LOCAL IP address 192.168.2.1/24
  * Local AREA network (where your standard "clients" are) on 192.168.0.0/24
  * And finally our MLVPN client router:
    - Private IP address 192.168.1.2/24 to join ADSL1
    - Private IP address 192.168.2.2/24 to join ADSL2
    - Private IP address 192.168.0.1/24 for LAN clients
    - Private IP address 10.42.42.2/30 on mlvpn0.

Yeah seems a bit complicated, but that's not that hard after all, we just have 4 routers.

Testing the basic configuration
===============================
At this time from "MLVPN client" you should be able to ping 192.168.2.1 and
192.168.1.1.

You should be able to access the internet using both links.

You can test it using standard routing.

Before we do anything: (Note: you may require installing iproute2)
```shell
root@mlvpnclient:~# ip route show
default via 192.168.1.1 dev eth0 
192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.1
192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.2
192.168.2.0/24 dev eth0  proto kernel  scope link  src 192.168.2.2 
```

This routing table means every packet to the internet will go thru 192.168.1.1.
We can test it:

```shell
root@mlvpnclient:~# ping -n -c2 -I192.168.1.2 ping.ovh.net
PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=42.1 ms
64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=41.7 ms
```
Ok I started to use "-I192.168.1.2" here. That's not mandatory in this
example, but this will become handy later. "-I" means we tell the ping command
to use 192.168.1.2 as source address of the packets we are sending to ping.ovh.net.

Now, we know our ADSL1 link is working properly.

Testing the second link will need us to modify the routing table.
```shell
root@mlvpnclient:~# ip route add 213.186.33.13 via 192.168.2.1
root@mlvpnclient:~# ip route show
default via 192.168.1.1 dev eth0 
213.186.33.13 via 192.168.2.2 dev eth0
192.168.0.0/24 dev eth0  proto kernel  scope link  src 192.168.0.1
192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.2
192.168.2.0/24 dev eth0  proto kernel  scope link  src 192.168.2.2 
```
Notice the new 213.186.33.13 (ping.ovh.net) added to the routing table.

Again, we can test the link:
```shell
root@mlvpnclient:~# ping -n -c2 -I192.168.2.2 ping.ovh.net
PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=62.4 ms
64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=61.1 ms
```
Noticed we changed the source address, and the latency is higher on ADSL2 by ~ 20ms.


Everything is fine, let's cleanup the routing table:
```shell
root@mlvpnclient:~# ip route del 213.186.33.13
```

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

```shell
root@mlvpnclient:~# echo 101 adsl1 >> /etc/iproute2/rt_tables
root@mlvpnclient:~# echo 102 adsl2 >> /etc/iproute2/rt_tables
```

Your configuration file should now look like this
```shell
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
```

We have "named" two new routing tables, but we did not create them.
/etc/iproute2/rt_tables file is optional.

We must add some routes to each table to activate them.
```shell
# Inserting routes in the adsl1 table
ip route add 192.168.1.0/24 dev eth0 scope link table adsl1
ip route add default via 192.168.1.1 dev eth0 table adsl1

# Inserting routes in the adsl2 table
ip route add 192.168.2.0/24 dev eth0 scope link table adsl2
ip route add default via 192.168.1.1 dev eth0 table adsl1

# ip rule is the source routing magic. This will redirect
# packets coming from source "X" to table "adsl1", "adsl2" or "default".
ip rule add from 192.168.1.0/24 table adsl1
ip rule add from 192.168.2.0/24 table adsl2
```
I've stripped root@machine for you, so you can copy paste ;-)

Testing
-------
First, show me your configuration! The first thing you should always do is
displaying ip rules. (Which routing table will be used when ?)
(Please note rules are applied in order from 0 to 32767)
```shell
root@mlvpnclient:~# ip rule list
  0:      from all lookup local
  32764:  from 192.168.1.0/24 lookup adsl1
  32765:  from 192.168.2.0/24 lookup adsl2
  32766:  from all lookup main
  32767:  from all lookup default
```

Then the routing tables:
```shell
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
```

Ping test
```shell
root@mlvpnclient:~# ping -c2 -n -I192.168.1.1 ping.ovh.net
PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=40.6 ms
64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=41.5 ms

root@mlvpnclient:~# ping -c2 -n -I192.168.2.1 ping.ovh.net
PING ping.ovh.net (213.186.33.13) 56(84) bytes of data.
64 bytes from 213.186.33.13: icmp_req=1 ttl=51 time=62.0 ms
64 bytes from 213.186.33.13: icmp_req=2 ttl=51 time=64.1 ms
```
Hey that's working fine !


TODO: the rest! (just as reminder: MLVPN source 192.168.1.1 for adsl1 192.168.2.1 for adsl2)