Debugging mlvpn
===============

gdb
---
```shell
sudo gdb -x gdb-cmds.txt --args mlvpn -c test/client.conf -u ed -v --debug
```

Debug tokens
------------
MLVPN can filter debug messages based on specific tokens using -D argument.

Tokens available:

    - config: configuration file related
    - control: control socket related (HTTP/json, UNIX socket)
    - dns: DNS related
    - net: network related (on line per packet AT LEAST)
    - privsep: privilage separation
    - protocol: protocol things (MOST COMMON to use for debugging)
    - reorder: reordering algorithm
    - rtt: latency measurements
    - tuntap: system tuntap
    - wrr: weighted round robin

