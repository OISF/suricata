
dnl ----------------------
dnl Initialization macros
dnl ----------------------

AC_INIT(htp/htp.h)
AC_CONFIG_HEADERS([config.h])


dnl -----------------------------------------------
dnl Package name and version number (user defined)
dnl -----------------------------------------------

GENERIC_LIBRARY_NAME=htp

GENERIC_MAJOR_VERSION=0
GENERIC_MINOR_VERSION=2
GENERIC_MICRO_VERSION=12

# API version (often = GENERIC_MAJOR_VERSION.GENERIC_MINOR_VERSION)
GENERIC_API_VERSION=1.0
AC_SUBST(GENERIC_API_VERSION)

# Shared library versioning
GENERIC_LIBRARY_VERSION=1:2:0
#                       | | |
#                +------+ | +---+
#                |        |     |
#             current:revision:age
#                |        |     |
#                |        |     +- increment if interfaces have been added
#                |        |        set to zero if interfaces have been removed
#                                  or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed


dnl --------------------------------
dnl Package name and version number
dnl --------------------------------

AC_SUBST(GENERIC_LIBRARY_VERSION)

PACKAGE=$GENERIC_LIBRARY_NAME
AC_SUBST(GENERIC_LIBRARY_NAME)

GENERIC_VERSION=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION.$GENERIC_MICRO_VERSION
GENERIC_RELEASE=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION
AC_SUBST(GENERIC_RELEASE)
AC_SUBST(GENERIC_VERSION)

VERSION=$GENERIC_VERSION

AM_INIT_AUTOMAKE($PACKAGE, $VERSION, no-define)

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE(htp-debug, [ --enable-htp-debug  Enable debug output], [ enable_htp_debug=yes ])
if test "$enable_htp_debug" = "yes"; then
    CFLAGS="${CFLAGS} -DHTP_DEBUG"
    echo "Debug mode enabled"
fi

dnl -----------------------------------------------
dnl Checks for programs.
dnl -----------------------------------------------

AC_PROG_CC
AM_PROG_LIBTOOL
AM_SANITY_CHECK

dnl -----------------------------------------------
dnl Checks for libs.
dnl -----------------------------------------------
AC_CHECK_HEADER(zlib.h,,[AC_ERROR(zlib.h not found ...)])
ZLIB=""
AC_CHECK_LIB(z, inflate,, ZLIB="no")
if test "$ZLIB" = "no"; then
    echo
    echo "   ERROR! zlib library not found"
    echo
    exit 1
fi

dnl -----------------------------------------------
dnl provides a read-only relocation table area in the final ELF
dnl -----------------------------------------------
AC_MSG_CHECKING(for -z relro)
TMPLDFLAGS="${LDFLAGS}"
LDFLAGS="${LDFLAGS} -z relro"
AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z relro"
AC_MSG_RESULT(yes),
AC_MSG_RESULT(no))
LDFLAGS="${TMPLDFLAGS}"


#check for os
AC_MSG_CHECKING([host os])

# If no host os was detected, try with uname
if test -z "$host" ; then
        host="`uname`"
fi
case "$host" in
       *-*-openbsd*)
                CFLAGS="${CFLAGS} -fgnu89-inline"
       ;;
esac
AC_MSG_RESULT(ok)


dnl -----------------------------------------------
dnl forces all relocations to be resolved at run-time
dnl -----------------------------------------------
AC_MSG_CHECKING(for -z now)
TMPLDFLAGS="${LDFLAGS}"
LDFLAGS="${LDFLAGS} -z now"
AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z now"
AC_MSG_RESULT(yes),
AC_MSG_RESULT(no))
LDFLAGS="${TMPLDFLAGS}"

CFLAGS="${CFLAGS} ${SECCFLAGS}"
LDFLAGS="${LDFLAGS} ${SECLDFLAGS}"

dnl -----------------------------------------------
dnl Generates Makefile's, configuration files and scripts
dnl -----------------------------------------------

AC_PREFIX_DEFAULT(/usr/local)

AC_OUTPUT(Makefile \
          htp.pc \
          htp/Makefile \
          test/Makefile
)
