AC_INIT([mlvpn], [1.0], [ed@zehome.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_CHECK_PROGS([RONN], [ronn], [:])
if test "$RONN" = :; then
    AC_MSG_WARN([Unable to build manpages without ronn! gem install ronn please.])
fi
AC_OUTPUT
