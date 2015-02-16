AC_INIT([mlvpn],
    m4_esyscmd([./git-version-gen .tarball-version]),
    [ed@zehome.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall silent-rules])
AM_SILENT_RULES([yes])
AC_PROG_CC
AC_CONFIG_HEADERS([config.h])

AC_GNU_SOURCE
AC_DEFINE([__USE_BSD], 1, [Enable BSD extensions])

AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
         [compiler does not accept __attribute__ on return types]) ]
)
if test "x$no_attrib_nonnull" != "x1" ; then
    AC_DEFINE([HAVE_ATTRIBUTE__NONNULL__], [1], [Have attribute nonnull])
fi

AC_CHECK_HEADERS([ \
    dirent.h \
    fcntl.h \
    sys/ndir.h \
    sys/dir.h \
    ndir.h \
    valgrind/valgrind.h
])

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
        AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
        AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
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

dnl Checks for library functions. Please keep in alphabetical order
AC_CHECK_FUNCS([ \
    closefrom \
    strlcat \
    strlcpy \
    strnvis \
    setproctitle \
    sysconf \
    vsnprintf
])

dnl Checks for libev
# lib ev
AC_CHECK_HEADERS([ev.h], [], [AC_MSG_ERROR("ev.h not found")])
AC_CHECK_LIB([ev], [ev_time], [
LIBS="-lev ${LIBS}"
AC_DEFINE([HAVE_LIBEV], [1], [ev_time in -lev])
], [AC_MSG_ERROR("libev not found")])

dnl Checks for libsodium
# libsodium
AC_CHECK_HEADERS([sodium.h], [], [AC_MSG_ERROR("sodium.h not found")])
AC_CHECK_LIB([sodium], [sodium_init], [
LIBS="-lsodium ${LIBS}"
AC_DEFINE([HAVE_LIBSODIUM], [1], [sodium_init in -lsodium])
], [AC_MSG_ERROR("libsodium not found")])

### Command lines options ###

### --enable-control (MLVPN simple http/CLI control system)
AC_ARG_ENABLE([control],
[  --disable-control              Turn off remote control system (cli and http)],
[case "${enableval}" in
    yes)
        AC_DEFINE(HAVE_MLVPN_CONTROL, 1, [Enable MLVPN Control])
        mlvpncontrol=true
    ;;
    no) mlvpncontrol=false ;;
    *)
        AC_MSG_ERROR([bad value ${enableval} for --enable-control])
    ;;
esac], [
    AC_DEFINE(HAVE_MLVPN_CONTROL, 1, [Enable MLVPN Control (set by default value)])
    mlvpncontrol=true
])
AM_CONDITIONAL([MLVPN_CONTROL], [test x$mlvpncontrol = xtrue ])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_CHECK_PROGS([RONN], [ronn], [:])
if test "$RONN" = :; then
    AC_MSG_WARN([Unable to build manpages without ronn! gem install ronn please.])
fi

dnl Enable extra warnings
CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-strict-aliasing -Wno-sign-compare"
AC_SUBST(CFLAGS)

AC_OUTPUT
