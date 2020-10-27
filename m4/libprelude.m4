dnl Autoconf macros for libprelude
dnl $id$

# Modified for LIBPRELUDE -- Thomas Andrejak
# Modified for LIBPRELUDE -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_LIBPRELUDE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for libprelude, and define LIBPRELUDE_PREFIX, LIBPRELUDE_CFLAGS, LIBPRELUDE_PTHREAD_CFLAGS,
dnl LIBPRELUDE_LDFLAGS, and LIBPRELUDE_LIBS
dnl
AC_DEFUN([AM_LIBPRELUDE],
[dnl
dnl Get the cflags and libraries from the pkg-config file
dnl
AC_ARG_ENABLE(libprelude, AC_HELP_STRING(--enable-libprelude, Define whether LibPrelude is required), libprelude_required="yes", enable_libprelude="yes")
if test x$enable_libprelude = xyes; then
  no_libprelude=""
  min_libprelude_version=ifelse([$1], ,0.1.0,$1)
  PKG_CHECK_MODULES([LIBPRELUDE], [libprelude >= $min_libprelude_version],
     [AC_CHECK_HEADER(libprelude/prelude.h, enable_libprelude=yes, enable_libprelude=no)],
     [enable_libprelude=no])
  if test "x$enable_libprelude" = xno ; then
    no_libprelude="no"
    ifelse([$3], , :, [$3])
  else
    AC_MSG_CHECKING(libprelude $min_libprelude_version usability)
  
    LIBPRELUDE_PREFIX=`pkg-config libprelude --variable=prefix`
    LIBPRELUDE_CONFIG_PREFIX=`pkg-config libprelude --variable=configprefix`
    libprelude_config_version=`pkg-config libprelude --modversion`

    ac_save_CFLAGS="$CFLAGS"
    ac_save_LDFLAGS="$LDFLAGS"
    ac_save_LIBS="$LIBS"
    CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
    LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
    LIBS="$LIBS $LIBPRELUDE_LIBS"
dnl
dnl Now check if the installed libprelude is sufficiently new. Also sanity
dnl checks the results of libprelude-config to some extent
dnl
     rm -f conf.libpreludetest
     AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>

int
main ()
{
    system ("touch conf.libpreludetest");

    if( strcmp( prelude_check_version(NULL), "$libprelude_config_version" ) )
    {
      printf("\n*** 'pkg-config libprelude --modversion' returned %s, but LIBPRELUDE (%s)\n",
             "$libprelude_config_version", prelude_check_version(NULL) );
      printf("*** was found! If pkg-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBPRELUDE.\n");
    }
    else if ( strcmp(prelude_check_version(NULL), LIBPRELUDE_VERSION ) ) {
        printf("\n*** LIBPRELUDE header file (version %s) does not match\n", LIBPRELUDE_VERSION);
        printf("*** library (version %s)\n", prelude_check_version(NULL) );
    }
    else {
      if ( prelude_check_version( "$min_libprelude_version" ) )
        return 0;
      else {
        printf("no\n*** An old version of LIBPRELUDE (%s) was found.\n",
                prelude_check_version(NULL) );
        printf("*** You need a version of LIBPRELUDE newer than %s. The latest version of\n",
               "$min_libprelude_version" );
        printf("*** LIBPRELUDE is always available from https://www.prelude-siem.org/project/prelude/files\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libprelude pkg-config file is\n");
        printf("*** being found.\n");
      }
    }
    return 1;
}
],, no_libprelude=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
    CFLAGS="$ac_save_CFLAGS"
    LIBS="$ac_save_LIBS"
    LDFLAGS="$ac_save_LDFLAGS"

    if test "x$no_libprelude" = x ; then
       AC_MSG_RESULT(yes)
       ifelse([$2], , :, [$2])
    else
       if test -f conf.libpreludetest ; then
        :
       else
          AC_MSG_RESULT(no)
          echo "*** Could not run libprelude test program, checking why..."
          CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
          LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
          LIBS="$LIBS $LIBPRELUDE_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libprelude/prelude.h>
],      [ return !!prelude_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBPRELUDE or finding the wrong"
          echo "*** version of LIBPRELUDE. If it is not finding LIBPRELUDE, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBPRELUDE was incorrectly installed"
          echo "*** or that you have moved LIBPRELUDE since it was installed. In the latter case, you"
          echo "*** may want to edit the libprelude-config script: $LIBPRELUDE_CONFIG" ])
           CFLAGS="$ac_save_CFLAGS"
           LDFLAGS="$ac_save_LDFLAGS"
           LIBS="$ac_save_LIBS"
       fi
       LIBPRELUDE_CFLAGS=""
       LIBPRELUDE_LDFLAGS=""
       LIBPRELUDE_LIBS=""
       ifelse([$3], , :, [$3])
    fi
    rm -f conf.libpreludetest
    AC_SUBST(LIBPRELUDE_CFLAGS)
    AC_SUBST(LIBPRELUDE_PTHREAD_CFLAGS)
    AC_SUBST(LIBPRELUDE_LDFLAGS)
    AC_SUBST(LIBPRELUDE_LIBS)
    AC_SUBST(LIBPRELUDE_PREFIX)
    AC_SUBST(LIBPRELUDE_CONFIG_PREFIX)
  fi

  m4_ifdef([LT_INIT],
           [AC_DEFINE([PRELUDE_APPLICATION_USE_LIBTOOL2], [], [Define whether application use libtool >= 2.0])],
           [])

  if test x$enable_libprelude = xno && test x$libprelude_required = xyes; then
     AC_MSG_ERROR([Could not find libprelude library])
  fi
fi
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
