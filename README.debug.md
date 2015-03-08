Debugging mlvpn
===============

gdb
---
```shell
echo follow-fork-mode child >/tmp/cmds
sudo gdb -x /tmp/cmds --args -c test/client.conf -u ed -vvv --debug
```

Debug tokens
------------
MLVPN can filter debug messages based on specific tokens using -D argument.

Tokens available:
    - config
    - control
    - dns
    - net
    - privsep
    - protocol
    - tuntap
    - wrr

