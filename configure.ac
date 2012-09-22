AC_INIT([mlvpn], [1.1], [ed@zehome.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall silent-rules])
AM_SILENT_RULES([yes])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_GNU_SOURCE
AC_DEFINE([__USE_BSD], 1, [Enable BSD extensions])

dnl Check and set Operating System
# Operating system specific tuntap
AC_CANONICAL_HOST
case $host_os in
    *linux*)
        AC_DEFINE(HAVE_LINUX, 1, [Linux])
        linux=true
    ;;
    *freebsd*)
        AC_DEFINE(HAVE_FREEBSD, 1, [FreeBSD])
        bsd=true
    ;;
    *openbsd*)
        AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
        bsd=true
    ;;
    *bsd*)
        AC_MSG_WARN("Unkown BSD system found. Might not work as expected!")
        AC_DEFINE(HAVE_BSD, 1, [BSD])
        bsd=true
    ;;
    *)
        AC_MSG_ERROR("Unknown operating system.")
    ;;
esac

AM_CONDITIONAL([LINUX], [test x$linux = xtrue])
AM_CONDITIONAL([BSD], [test x$bsd = xtrue])

# --enable-control (MLVPN simple http/CLI control system)
AC_ARG_ENABLE([control],
[  --disable-control              Turn off remote control system (cli and http)],
[case "${enableval}" in
    yes)
        AC_DEFINE(HAVE_MLVPN_CONTROL, 1, [Enable MVPN Control])
        mlvncontrol=true
    ;;
    no) mlvncontrol=false ;;
    *)
        AC_MSG_ERROR([bad value ${enableval} for --enable-control])
    ;;
esac], [
    AC_DEFINE(HAVE_MLVPN_CONTROL, 1, [Enable MVPN Control (set by default value)])
    mlvpncontrol=true
])
AM_CONDITIONAL([MLVPN_CONTROL], [test x$mlvpncontrol = xtrue ])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_CHECK_PROGS([RONN], [ronn], [:])
if test "$RONN" = :; then
    AC_MSG_WARN([Unable to build manpages without ronn! gem install ronn please.])
fi

AC_OUTPUT
