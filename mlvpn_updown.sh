#!/bin/bash

error=0 ; trap "error=$((error|1))" ERR

##############################################################################
# UP/DOWN script for MLVPN.
#
# MLVPN calls this script with at least 2 arguments:
# $1 is the interface name
# $2 is the "command"
#
# command can be:
#    - "tuntap_up"
#    - "tuntap_down"
#    - "rtun_up" $3 is rtun_name
#    - "rtun_down" $3 is rtun_name
#
# rtun_up is called when successfully connected to the other side.
# rtun_down is called when disconnected/timedout from the other side.
#
##############################################################################

tuntap_intf="$1"
newstatus="$2"

[ -z "$newstatus" ] && exit 1

(
if [ "$newstatus" = "tuntap_up" ]; then
    echo "Setting up interface $tuntap_intf"
    /sbin/ifconfig $tuntap_intf 192.168.66.10 netmask 255.255.255.0 mtu 1400 up
elif [ "$newstatus" = "tuntap_down" ]; then
    echo "Shutting down interface $tuntap_intf"
    /sbin/ifconfig $tuntap_intf down
elif [ "$newstatus" = "rtun_up" ]; then
    echo "MLVPN informed me rtun [$3] is up"
elif [ "$newstatus" = "rtun_down" ]; then
    echo "MLVPN informed me rtun [$3] is down."
fi

) >> /var/log/mlvpn_commands.log 2>&1

exit $errors
