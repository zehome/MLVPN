#!/bin/sh -e

### BEGIN INIT INFO
# Provides:          mlvpn
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Should-Start:      network-manager
# Should-Stop:       network-manager
# X-Start-Before:    $x-display-manager gdm kdm xdm wdm ldm sdm nodm
# X-Interactive:     true
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: MLVPN Link Aggregator
# Description: This script will start MLVPN tunnels as specified
#              in /etc/default/mlvpn and /etc/mlvpn/*.conf
### END INIT INFO

# Original version by Robert Leslie
# <rob@mars.org>, edited by iwj and cs
# Modified for openvpn by Alberto Gonzalez Iniesta <agi@inittab.org>
# Modified for restarting / starting / stopping single tunnels by Richard Mueller <mueller@teamix.net>
# Modified for mlvpn by Laurent Coustet <ed@zehome.com>

. /lib/lsb/init-functions

test $DEBIAN_SCRIPT_DEBUG && set -v -x

DAEMON=/usr/sbin/mlvpn
USER=mlvpn
DESC="virtual private network daemon"
CONFIG_DIR=/etc/mlvpn
test -x $DAEMON || exit 0
test -d $CONFIG_DIR || exit 0

# Directory used by mlvpn chroot (mlvpn user $HOME)
[ -d /run/mlvpn ] || mkdir /run/mlvpn

# Source defaults file; edit that file to configure this script.
AUTOSTART="all"
if test -e /etc/default/mlvpn ; then
  . /etc/default/mlvpn
fi

start_vpn () {
    log_progress_msg "$NAME"
    STATUS=0

    start-stop-daemon --start --quiet --oknodo \
        --pidfile /run/mlvpn.$NAME.pid \
        --background \
        --make-pidfile \
        --exec $DAEMON -- -c $CONFIG_DIR/$NAME.conf --user=$USER || STATUS=1
}
stop_vpn () {
  kill `cat $PIDFILE` || true
  rm -f $PIDFILE
  rm -f /var/mlvpn.$NAME.status 2> /dev/null
}

case "$1" in
start)
  log_daemon_msg "Starting $DESC"

  # autostart VPNs
  if test -z "$2" ; then
    # check if automatic startup is disabled by AUTOSTART=none
    if test "x$AUTOSTART" = "xnone" -o -z "$AUTOSTART" ; then
      log_warning_msg " Autostart disabled."
      exit 0
    fi
    if test -z "$AUTOSTART" -o "x$AUTOSTART" = "xall" ; then
      # all VPNs shall be started automatically
      for CONFIG in `cd $CONFIG_DIR; ls *.conf 2> /dev/null`; do
        NAME=${CONFIG%%.conf}
        start_vpn
      done
    else
      # start only specified VPNs
      for NAME in $AUTOSTART ; do
        if test -e $CONFIG_DIR/$NAME.conf ; then
          start_vpn
        else
          log_failure_msg "No such VPN: $NAME"
          STATUS=1
        fi
      done
    fi
  #start VPNs from command line
  else
    while shift ; do
      [ -z "$1" ] && break
      if test -e $CONFIG_DIR/$1.conf ; then
        NAME=$1
        start_vpn
      else
       log_failure_msg " No such VPN: $1"
       STATUS=1
      fi
    done
  fi
  log_end_msg ${STATUS:-0}

  ;;
stop)
  log_daemon_msg "Stopping $DESC"

  if test -z "$2" ; then
    for PIDFILE in `ls /run/mlvpn.*.pid 2> /dev/null`; do
      NAME=`echo $PIDFILE | cut -c18-`
      NAME=${NAME%%.pid}
      stop_vpn
      log_progress_msg "$NAME"
    done
  else
    while shift ; do
      [ -z "$1" ] && break
      if test -e /run/mlvpn.$1.pid ; then
        PIDFILE=`ls /run/mlvpn.$1.pid 2> /dev/null`
        NAME=`echo $PIDFILE | cut -c18-`
        NAME=${NAME%%.pid}
        stop_vpn
        log_progress_msg "$NAME"
      else
        log_failure_msg " (failure: No such VPN is running: $1)"
      fi
    done
  fi
  log_end_msg 0
  ;;
# Only 'reload' running VPNs. New ones will only start with 'start' or 'restart'.
reload|force-reload)
 log_daemon_msg "Reloading $DESC"
  for PIDFILE in `ls /run/mlvpn.*.pid 2> /dev/null`; do
    NAME=`echo $PIDFILE | cut -c18-`
    NAME=${NAME%%.pid}
    stop_vpn
    sleep 1
    start_vpn
    log_progress_msg "(restarted)"
  done
  log_end_msg 0
  ;;

restart)
  shift
  $0 stop ${@}
  sleep 1
  $0 start ${@}
  ;;
cond-restart)
  log_daemon_msg "Restarting $DESC."
  for PIDFILE in `ls /run/mlvpn.*.pid 2> /dev/null`; do
    NAME=`echo $PIDFILE | cut -c18-`
    NAME=${NAME%%.pid}
    stop_vpn
    sleep 1
    start_vpn
  done
  log_end_msg 0
  ;;
status)
  GLOBAL_STATUS=0
  if test -z "$2" ; then
    # We want status for all defined VPNs.
    # Returns success if all autostarted VPNs are defined and running
    if test "x$AUTOSTART" = "xnone" ; then
      # Consider it a failure if AUTOSTART=none
      log_warning_msg "No VPN autostarted"
      GLOBAL_STATUS=1
    else
      if ! test -z "$AUTOSTART" -o "x$AUTOSTART" = "xall" ; then
        # Consider it a failure if one of the autostarted VPN is not defined
        for VPN in $AUTOSTART ; do
          if ! test -f $CONFIG_DIR/$VPN.conf ; then
            log_warning_msg "VPN '$VPN' is in AUTOSTART but is not defined"
            GLOBAL_STATUS=1
          fi
        done
      fi
    fi
    for CONFIG in `cd $CONFIG_DIR; ls *.conf 2> /dev/null`; do
      NAME=${CONFIG%%.conf}
      # Is it an autostarted VPN ?
      if test -z "$AUTOSTART" -o "x$AUTOSTART" = "xall" ; then
        AUTOVPN=1
      else
        if test "x$AUTOSTART" = "xnone" ; then
          AUTOVPN=0
        else
          AUTOVPN=0
          for VPN in $AUTOSTART; do
            if test "x$VPN" = "x$NAME" ; then
              AUTOVPN=1
            fi
          done
        fi
      fi
      if test "x$AUTOVPN" = "x1" ; then
        # If it is autostarted, then it contributes to global status
        status_of_proc -p /run/mlvpn.${NAME}.pid mlvpn "VPN '${NAME}'" || GLOBAL_STATUS=1
      else
        status_of_proc -p /run/mlvpn.${NAME}.pid mlvpn "VPN '${NAME}' (non autostarted)" || true
      fi
    done
  else
    # We just want status for specified VPNs.
    # Returns success if all specified VPNs are defined and running
    while shift ; do
      [ -z "$1" ] && break
      NAME=$1
      if test -e $CONFIG_DIR/$NAME.conf ; then
        # Config exists
        status_of_proc -p /run/mlvpn.${NAME}.pid mlvpn "VPN '${NAME}'" || GLOBAL_STATUS=1
      else
        # Config does not exist
        log_warning_msg "VPN '$NAME': missing $CONFIG_DIR/$NAME.conf file !"
        GLOBAL_STATUS=1
      fi
    done
  fi
  exit $GLOBAL_STATUS
  ;;
*)
  echo "Usage: $0 {start|stop|reload|restart|force-reload|cond-restart|soft-restart|status}" >&2
  exit 1
  ;;
esac

exit 0

# vim:set ai sts=2 sw=2 tw=0:
