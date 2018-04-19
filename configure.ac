AC_PREREQ([2.64])
AC_INIT([mlvpn],
    m4_esyscmd([./git-version-gen .tarball-version]),
    [ed@zehome.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 doc/examples/Makefile
                 doc/examples/systemd/Makefile
                 src/Makefile
                 man/Makefile])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([CONFIGURE_ARGS], [$ac_configure_args])
AM_INIT_AUTOMAKE([foreign -Wall -Wextra silent-rules])

AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

# Checks
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_SED

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

AC_CHECK_DECLS(
    [res_init],
    [AC_CHECK_LIB(resolv, res_init)],
    [], [
      #include <netinet/in.h>
      #include <arpa/nameser.h>
      #include <resolv.h>
    ]
)

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
    *netbsd*)
        AC_DEFINE(HAVE_NETBSD, 1, [NetBSD])
        bsd=true
    ;;
    *openbsd*)
        AC_DEFINE(HAVE_OPENBSD, 1, [OpenBSD])
        AC_DEFINE([HAVE_ATTRIBUTE__SENTINEL__], [1], [OpenBSD's gcc has sentinel])
        AC_DEFINE([HAVE_ATTRIBUTE__BOUNDED__], [1], [OpenBSD's gcc has bounded])
        bsd=true
    ;;
    *bsd*)
        AC_MSG_WARN("Unsupported BSD system found. Might not work as expected.")
        AC_DEFINE(HAVE_BSD, 1, [BSD])
        bsd=true
    ;;
    *darwin*)
        AC_DEFINE(HAVE_DARWIN, 1, [DARWIN])
        darwin=true
    ;;
    *)
        AC_MSG_ERROR("Unsupported operating system.")
    ;;
esac

AM_CONDITIONAL([LINUX], [test x$linux = xtrue])
AM_CONDITIONAL([BSD], [test x$bsd = xtrue])
AM_CONDITIONAL([DARWIN], [test x$darwin = xtrue])

dnl Checks for library functions. Please keep in alphabetical order
AC_CHECK_FUNCS([ \
    closefrom \
    pledge \
    setproctitle \
    setresgid \
    setresuid \
    strlcat \
    strlcpy \
    strnvis \
    sysconf \
    vsnprintf
])

AM_CONDITIONAL([HAVE_CLOSEFROM], [test x"$have_closefrom" = x"true"])
AM_CONDITIONAL([HAVE_PLEDGE], [test x"$have_pledge" = x"true"])
AM_CONDITIONAL([HAVE_SETPROCTITLE], [test x"$have_setproctitle" = x"true"])
AM_CONDITIONAL([HAVE_STRLCAT], [test x"$have_strlcat" = x"true"])
AM_CONDITIONAL([HAVE_STRLCPY], [test x"$have_strlcpy" = x"true"])
AM_CONDITIONAL([HAVE_STRNVIS], [test x"$have_strnvis" = x"true"])

AC_CACHE_SAVE

dnl checks for libsodium
PKG_CHECK_MODULES([libsodium], [libsodium >= 0.6], [], [
    AC_CHECK_HEADERS([sodium.h], [], [AC_MSG_ERROR("sodium.h not found")])
    AC_CHECK_LIB([sodium], [sodium_init], [
        libsodium_LIBS="-lsodium"
        AC_DEFINE([HAVE_LIBSODIUM], [1], [sodium_init in -lsodium])
    ], [AC_MSG_ERROR("libsodium not found")])
])

dnl checks for libev
# lib ev
PKG_CHECK_MODULES([libev], [libev], [], [
    AC_CHECK_HEADERS([ev.h], [], [AC_MSG_ERROR("ev.h not found")])
    AC_CHECK_LIB([ev], [ev_time], [
        libev_LIBS="-lev"
        AC_DEFINE([HAVE_LIBEV], [1], [ev_time in -lev])
    ], [AC_MSG_ERROR("libev not found")])
])


### Command lines options ###
mlvpn_ARG_ENABLE([control], [remote control system (cli and http)], [yes])
mlvpn_ARG_ENABLE([filters], [libpcap support for filters], [yes])
mlvpn_ARG_WITH([install-examples], [install example files], [yes])
AM_CONDITIONAL([INSTALL_EXAMPLES], [test x"$with_install_examples" = x"yes" ])

# Systemd
mlvpn_ARG_WITH([systemdsystemunitdir], [Directory for systemd service files],
              [$(pkg-config --variable=systemdsystemunitdir systemd 2> /dev/null)])
    AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
    AM_CONDITIONAL(HAVE_SYSTEMDSYSTEMUNITDIR,
        [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])
mlvpn_ARG_WITH([systemdsystemgeneratordir], [Directory for systemd generators],
              [$(pkg-config --variable=systemdsystemgeneratordir systemd 2> /dev/null)])
    AC_SUBST([systemdsystemgeneratordir], [$with_systemdsystemgeneratordir])
    AM_CONDITIONAL(HAVE_SYSTEMDSYSTEMGENERATORDIR,
        [test -n "$with_systemdsystemgeneratordir" -a "x$with_systemdsystemgeneratordir" != xno ])

mlvpn_ARG_WITH([systemdtmpfilesdir], [Directory for systemd tmpfiles],
              [$(pkg-config --variable=tmpfilesdir systemd 2> /dev/null)])
    AC_SUBST([systemdtmpfilesdir], [$with_systemdtmpfilesdir])
    AM_CONDITIONAL(HAVE_SYSTEMDTMPFILESDIR,
        [test -n "$with_systemdtmpfilesdir" -a "x$with_systemdtmpfilesdir" != xno ])

dnl checks for libpcap
# Default values
AM_CONDITIONAL([HAVE_FILTERS], [false])
AS_IF([test x"$enable_filters" = x"yes"], [
    AM_CONDITIONAL([HAVE_FILTERS], [true])
    AC_DEFINE([HAVE_FILTERS], [], [filters enabled])
    dnl checks for libpcap
    PKG_CHECK_MODULES([libpcap], [libpcap], [], [
        AC_CHECK_HEADERS([pcap.h], [], [AC_MSG_ERROR("pcap.h not found")])
        AC_CHECK_LIB([pcap], [pcap_open_dead], [
            libpcap_LIBS="-lpcap"
        ], [
            AC_MSG_ERROR("libpcap not found")
        ])
    ])
])

AC_CHECK_PROGS([RONN], [ronn], [])
AM_CONDITIONAL(HAVE_RONN, [test x"$RONN" != "x"])
if test x"$RONN" = "x"; then
    AC_MSG_WARN([ronn is not available, skip manpages build.])
fi

dnl Enable extra warnings
CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-strict-aliasing -Wno-sign-compare"
AC_SUBST(CFLAGS)

AC_OUTPUT
