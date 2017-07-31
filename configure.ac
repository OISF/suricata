    AC_INIT(suricata, 4.0.0-dev)
    m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])
    AC_CONFIG_HEADERS([config.h])
    AC_CONFIG_SRCDIR([src/suricata.c])
    AC_CONFIG_MACRO_DIR(m4)
    AM_INIT_AUTOMAKE

    AC_LANG_C
    AC_PROG_CC_C99
    AC_PROG_LIBTOOL
    PKG_PROG_PKG_CONFIG

    dnl Taken from https://llvm.org/svn/llvm-project/llvm/trunk/autoconf/configure.ac
    dnl check if we compile using clang or gcc. On some systems the gcc binary is
    dnl is actually clang, so do a compile test.
    AC_MSG_CHECKING([whether GCC or Clang is our compiler])
    AC_LANG_PUSH([C])
    compiler=unknown
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#if ! __clang__
                                        #error
                                        #endif
                                      ]])],
                       compiler=clang,
                      [AC_COMPILE_IFELSE([AC_LANG_SOURCE([[#if ! __GNUC__
                                                           #error
                                                           #endif
                                                         ]])],
                       compiler=gcc, [])])
    AC_LANG_POP([C])
    AC_MSG_RESULT([${compiler}])

    case "$compiler" in
        clang)
            CLANG_CFLAGS="-Wextra -Werror-implicit-function-declaration -Wno-error=unused-command-line-argument"
            AC_MSG_CHECKING([clang __sync_bool_compare_and_swap support])
            AC_TRY_COMPILE([#include <stdio.h>],
                [ unsigned int i = 0; (void)__sync_bool_compare_and_swap(&i, 1, 1);],
                [
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4], [1], [Fake GCC atomic support])
                    AC_DEFINE([__GCC_HAVE_SYNC_COMPARE_AND_SWAP_8], [1], [Fake GCC atomic support])
                    AC_MSG_RESULT([yes]) ],
                [AC_MSG_RESULT([no])])
            AC_SUBST(CLANG_CFLAGS)
            ;;
        gcc)
            dnl get gcc version
            AC_MSG_CHECKING([gcc version])
                    gccver=$($CC -dumpversion)
                    gccvermajor=$(echo $gccver | cut -d . -f1)
                    gccverminor=$(echo $gccver | cut -d . -f2)
                    gccvernum=$(expr $gccvermajor "*" 100 + $gccverminor)
            AC_MSG_RESULT($gccver)

            if test "$gccvernum" -ge "400"; then
                dnl gcc 4.0 or later
                GCC_CFLAGS="-Wextra -Werror-implicit-function-declaration"
            else
                GCC_CFLAGS="-W"
            fi
            AC_SUBST(GCC_CFLAGS)
            ;;
        *)
            AC_MSG_WARN([unsupported/untested compiler, this may or may not work])
            ;;
    esac

    # Checks for programs.
    AC_PROG_AWK
    AC_PROG_CC
    AC_PROG_CPP
    AC_PROG_INSTALL
    AC_PROG_LN_S
    AC_PROG_MAKE_SET

    AC_PATH_PROG(HAVE_PKG_CONFIG, pkg-config, "no")
    if test "$HAVE_PKG_CONFIG" = "no"; then
        echo
        echo "   ERROR! pkg-config not found, go get it  "
        echo "   http://pkg-config.freedesktop.org/wiki/ "
        echo "   or install from your distribution       "
        echo
        exit 1
    fi

    AC_ARG_ENABLE(python,
           AS_HELP_STRING([--enable-python], [Enable python]),,[enable_python=yes])
    AC_PATH_PROGS(HAVE_PYTHON, python python2 python2.7, "no")
    if test "x$enable_python" = "xno" ; then
        echo
        echo "   Warning! python disabled, you will not be      "
        echo "   able to install suricatasc unix socket client   "
        echo
        enable_python="no"
    fi
    if test "$HAVE_PYTHON" = "no"; then
        echo
        echo "   Warning! python not found, you will not be     "
        echo "   able to install suricatasc unix socket client   "
        echo
        enable_python="no"
    fi
    AM_CONDITIONAL([HAVE_PYTHON], [test "x$enable_python" = "xyes"])

    AC_PATH_PROG(HAVE_WGET, wget, "no")
    if test "$HAVE_WGET" = "no"; then
        AC_PATH_PROG(HAVE_CURL, curl, "no")
        if test "$HAVE_CURL" = "no"; then
            echo
            echo "   Warning curl or wget not found, you won't be able to"
            echo "   download latest ruleset with 'make install-rules'"
        fi
    fi
    AM_CONDITIONAL([HAVE_FETCH_COMMAND], [test "x$HAVE_WGET" != "xno" || test "x$HAVE_CURL" != "xno"])
    AM_CONDITIONAL([HAVE_WGET_COMMAND], [test "x$HAVE_WGET" != "xno"])

    # Checks for libraries.

    # Checks for header files.
    AC_CHECK_HEADERS([stddef.h])
    AC_CHECK_HEADERS([arpa/inet.h assert.h ctype.h errno.h fcntl.h inttypes.h])
    AC_CHECK_HEADERS([getopt.h])
    AC_CHECK_HEADERS([limits.h netdb.h netinet/in.h poll.h sched.h signal.h])
    AC_CHECK_HEADERS([stdarg.h stdint.h stdio.h stdlib.h stdbool.h string.h strings.h sys/ioctl.h])
    AC_CHECK_HEADERS([syslog.h sys/prctl.h sys/socket.h sys/stat.h sys/syscall.h])
    AC_CHECK_HEADERS([sys/time.h time.h unistd.h])
    AC_CHECK_HEADERS([sys/ioctl.h linux/if_ether.h linux/if_packet.h linux/filter.h])
    AC_CHECK_HEADERS([linux/ethtool.h linux/sockios.h])
    AC_CHECK_HEADER(glob.h,,[AC_ERROR(glob.h not found ...)])
    AC_CHECK_HEADERS([dirent.h fnmatch.h])
    AC_CHECK_HEADERS([sys/resource.h sys/types.h sys/un.h])

    AC_CHECK_HEADERS([sys/socket.h net/if.h sys/mman.h linux/if_arp.h], [], [],
    [[#ifdef HAVE_SYS_SOCKET_H
        #include <sys/types.h>
        #include <sys/socket.h>
        #endif
    ]])

    AC_CHECK_HEADERS([windows.h winsock2.h ws2tcpip.h w32api/wtypes.h], [], [],
                    [[
                        #ifndef _X86_
                        #define _X86_
                        #endif
                     ]])
    AC_CHECK_HEADERS([w32api/winbase.h wincrypt.h], [], [],
                    [[
                        #ifndef _X86_
                        #define _X86_
                        #endif
                        #include <windows.h>
                     ]])

    # Checks for typedefs, structures, and compiler characteristics.
    AC_C_INLINE
    AC_TYPE_PID_T
    AC_TYPE_SIZE_T
    AC_TYPE_INT32_T
    AC_TYPE_UINT16_T
    AC_TYPE_UINT32_T
    AC_TYPE_UINT64_T
    AC_TYPE_UINT8_T
    AC_HEADER_STDBOOL

    # Checks for library functions.
    AC_FUNC_MALLOC
    AC_FUNC_REALLOC
    AC_CHECK_FUNCS([gettimeofday memset strcasecmp strchr strdup strerror strncasecmp strtol strtoul memchr memrchr clock_gettime])

    OCFLAGS=$CFLAGS
    CFLAGS=""
    AC_CHECK_FUNCS([strlcpy strlcat])
    CFLAGS=$OCFLAGS

    # Add large file support
    AC_SYS_LARGEFILE

    #check for os
    AC_MSG_CHECKING([host os])

    # lua pkg-config name differs per OS
    LUA_PC_NAME="lua5.1"
    LUA_LIB_NAME="lua5.1"

    # If no host os was detected, try with uname
    if test -z "$host" ; then
	    host="`uname`"
    fi
    echo -n "installation for $host OS... "

    e_magic_file=""
    e_magic_file_comment="#"
    PCAP_LIB_NAME="pcap"
    case "$host" in
        *-*-*freebsd*)
            LUA_PC_NAME="lua-5.1"
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_FREEBSD"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet11"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/local/lib/libnet11"
            ;;
        *-*-openbsd*)
            LUA_PC_NAME="lua51"
            CFLAGS="${CFLAGS} -D__OpenBSD__"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet-1.1"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -I/usr/local/lib/libnet-1.1"
            ;;
        *darwin*|*Darwin*)
            LUA_PC_NAME="lua-5.1"
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_DARWIN"
            CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
            LDFLAGS="${LDFLAGS} -L/opt/local/lib"
            ;;
        *-*-linux*)
            #for now do nothing
	    RUST_LDADD="-ldl -lrt -lm"
            ;;
        *-*-mingw32*)
            CFLAGS="${CFLAGS} -DOS_WIN32"
            LDFLAGS="${LDFLAGS} -lws2_32"
            WINDOWS_PATH="yes"
            PCAP_LIB_NAME="wpcap"
            ;;
        *-*-cygwin)
            LUA_PC_NAME="lua"
            LUA_LIB_NAME="lua"
            WINDOWS_PATH="yes"
            PCAP_LIB_NAME="wpcap"
            ;;
        *-*-solaris*)
            AC_MSG_WARN([support for Solaris/Illumos/SunOS is experimental])
            LDFLAGS="${LDFLAGS} -lsocket -lnsl"
            ;;
        *)
            AC_MSG_WARN([unsupported OS this may or may not work])
            ;;
    esac
    AC_MSG_RESULT(ok)

    # enable modifications for AFL fuzzing
    AC_ARG_ENABLE(afl,
           AS_HELP_STRING([--enable-afl], Enable AFL fuzzing logic[])], [enable_afl="$enableval"],[enable_afl=no])

    AS_IF([test "x$enable_afl" = "xyes"], [
        AC_DEFINE([AFLFUZZ_NO_RANDOM], [1], [Disable all use of random functions])
        AC_DEFINE([AFLFUZZ_DISABLE_MGTTHREADS], [1], [Disable all management threads])
        AC_DEFINE([AFLFUZZ_PCAP_RUNMODE], [1], [Enable special AFL 'single' runmode])
        AC_DEFINE([AFLFUZZ_CONF_TEST], [1], [Enable special --afl-parse-rules commandline option])
        AC_DEFINE([AFLFUZZ_APPLAYER], [1], [Enable --afl-$proto-request commandline option])
        AC_DEFINE([AFLFUZZ_MIME], [1], [Enable --afl-mime commandline option])
        AC_DEFINE([AFLFUZZ_DECODER], [1], [Enable --afl-decoder-$proto commandline option])
        AC_DEFINE([AFLFUZZ_DER], [1], [Enable --afl-der commandline option])
        AC_DEFINE([AFLFUZZ_RULES], [1], [Enable --afl-rules commandline option])

        # test for AFL PERSISTANT_MODE support
        CFLAGS_ORIG=$CFLAGS
        CFLAGS="-Werror"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[while (__AFL_LOOP(1000))]])],
                [AC_DEFINE([AFLFUZZ_PERSISTANT_MODE], [1], [Enable AFL PERSISTANT_MODE])],
                [])
        CFLAGS=$CFLAGS_ORIG
    ])

  # disable TLS on user request
    AC_ARG_ENABLE(threading-tls,
           AS_HELP_STRING([--disable-threading-tls], [Disable TLS (thread local storage)]), [enable_tls="$enableval"],[enable_tls=yes])
    AS_IF([test "x$enable_tls" = "xyes"], [
        # check if our target supports thread local storage
        AC_MSG_CHECKING(for thread local storage __thread support)
        AC_TRY_COMPILE([#include <stdlib.h>],
            [ static __thread int i; i = 1; i++; ],
            [AC_DEFINE([TLS], [1], [Thread local storage])
             AC_MSG_RESULT([yes]) ],
            [AC_MSG_RESULT([no])])
    ])

    #Enable support for gcc compile time security options. There is no great way to do detection of valid cflags that I have found
    #AX_CFLAGS_GCC_OPTION don't seem to do a better job than the code below and are a pain because of extra m4 files etc.
    #These flags seem to be supported on CentOS 5+, Ubuntu 8.04+, and FedoreCore 11+
    #Options are taken from https://wiki.ubuntu.com/CompilerFlags
    AC_ARG_ENABLE(gccprotect,
           AS_HELP_STRING([--enable-gccprotect], [Detect and use gcc hardening options]),,[enable_gccprotect=no])

    AS_IF([test "x$enable_gccprotect" = "xyes"], [
        #buffer overflow protection
        AC_MSG_CHECKING(for -fstack-protector)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -fstack-protector"
        AC_TRY_LINK(,,SECCFLAGS="-fstack-protector"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #compile-time best-practices errors for certain libc functions, provides checks of buffer lengths and memory regions
        AC_MSG_CHECKING(for -D_FORTIFY_SOURCE=2)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -D_FORTIFY_SOURCE=2"
        AC_TRY_COMPILE(,,SECCFLAGS="${SECCFLAGS} -D_FORTIFY_SOURCE=2"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #compile-time warnings about misuse of format strings
        AC_MSG_CHECKING(for -Wformat -Wformat-security)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -Wformat -Wformat-security"
        AC_TRY_COMPILE(,,SECCFLAGS="${SECCFLAGS} -Wformat -Wformat-security"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        CFLAGS="${TMPCFLAGS}"

        #provides a read-only relocation table area in the final ELF
        AC_MSG_CHECKING(for -z relro)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z relro"
        AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z relro"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        LDFLAGS="${TMPLDFLAGS}"

        #forces all relocations to be resolved at run-time
        AC_MSG_CHECKING(for -z now)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z now"
        AC_TRY_LINK(,,SECLDFLAGS="${SECLDFLAGS} -z now"
            AC_MSG_RESULT(yes),
            AC_MSG_RESULT(no))
        LDFLAGS="${TMPLDFLAGS}"

        AC_SUBST(SECCFLAGS)
        AC_SUBST(SECLDFLAGS)
    ])

    #enable profile generation
    AC_ARG_ENABLE(gccprofile,
           AS_HELP_STRING([--enable-gccprofile], [Enable gcc profile info i.e -pg flag is set]),,[enable_gccprofile=no])
    AS_IF([test "x$enable_gccprofile" = "xyes"], [
        CFLAGS="${CFLAGS} -pg"
    ])

    #enable gcc march=native gcc 4.2 or later
    AC_ARG_ENABLE(gccmarch_native,
           AS_HELP_STRING([--enable-gccmarch-native], [Enable gcc march=native gcc 4.2 and later only]),,[enable_gccmarch_native=yes])
    AS_IF([test "x$enable_gccmarch_native" = "xyes"], [
        case "$host" in
            *powerpc*)
                ;;
            *)
            OFLAGS="$CFLAGS"
            CFLAGS="$CFLAGS -march=native"
            AC_MSG_CHECKING([checking if $CC supports -march=native])
            AC_COMPILE_IFELSE(  [AC_LANG_PROGRAM([[#include <stdlib.h>]])],
                        [
                          AC_MSG_RESULT([yes])
                          OPTIMIZATION_CFLAGS="-march=native"
                          AC_SUBST(OPTIMIZATION_CFLAGS)
                        ],
                        [
                          AC_MSG_RESULT([no])
                          CFLAGS="$OFLAGS"
                          enable_gccmarch_native=no
                        ]
                     )
                ;;
        esac
    ])

# options

  # enable the running of unit tests
    AC_ARG_ENABLE(unittests,
           AS_HELP_STRING([--enable-unittests], [Enable compilation of the unit tests]),,[enable_unittests=no])
    AS_IF([test "x$enable_unittests" = "xyes"], [
        AC_DEFINE([UNITTESTS],[1],[Enable built-in unittests])
    ])
    AM_CONDITIONAL([BUILD_UNITTESTS], [test "x$enable_unittests" = "xyes"])

  # enable workaround for old barnyard2 for unified alert output
    AC_ARG_ENABLE(old-barnyard2,
           AS_HELP_STRING([--enable-old-barnyard2], [Use workaround for old barnyard2 in unified2 output]),,[enable_old_barnyard2=no])
    AS_IF([test "x$enable_old_barnyard2" = "xyes"], [
        AC_DEFINE([HAVE_OLD_BARNYARD2],[1],[Use workaround for old barnyard2 in unified2 output])
    ])

  # enable debug output
    AC_ARG_ENABLE(debug,
           AS_HELP_STRING([--enable-debug], [Enable debug output]),,[enable_debug=no])
    AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE([DEBUG],[1],[Enable debug output])
    ])
    AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = "xyes"])

  # enable debug validation functions & macro's output
    AC_ARG_ENABLE(debug-validation,
           AS_HELP_STRING([--enable-debug-validation], [Enable (debug) validation code output]),,[enable_debug_validation=no])
    AS_IF([test "x$enable_debug_validation" = "xyes"], [
        if test "$enable_unittests" = "yes"; then
            AC_MSG_ERROR([debug_validation can't be enabled with enabled unittests!])
        else
            AC_DEFINE([DEBUG_VALIDATION],[1],[Enable (debug) validation code output])
        fi
    ])

  # profiling support
    AC_ARG_ENABLE(profiling,
           AS_HELP_STRING([--enable-profiling], [Enable performance profiling]),,[enable_profiling=no])
    AS_IF([test "x$enable_profiling" = "xyes"], [
    case "$host" in
        *-*-openbsd*)
            AC_MSG_ERROR([profiling is not supported on OpenBSD])
            ;;
        *)
            AC_DEFINE([PROFILING],[1],[Enable performance profiling])
            ;;
    esac
    ])

  # profiling support, locking
    AC_ARG_ENABLE(profiling-locks,
           AS_HELP_STRING([--enable-profiling-locks], [Enable performance profiling for locks]),,[enable_profiling_locks=no])
    AS_IF([test "x$enable_profiling_locks" = "xyes"], [
        AC_DEFINE([PROFILING],[1],[Enable performance profiling])
        AC_DEFINE([PROFILE_LOCKING],[1],[Enable performance profiling for locks])
    ])

  # enable support for IPFW
    AC_ARG_ENABLE(ipfw,
            AS_HELP_STRING([--enable-ipfw], [Enable FreeBSD IPFW support for inline IDP]),,[enable_ipfw=no])
    AS_IF([test "x$enable_ipfw" = "xyes"], [
        AC_DEFINE([IPFW],[1],[Enable FreeBSD IPFW support for inline IDP])
    ])

    AC_ARG_ENABLE(coccinelle,
           AS_HELP_STRING([--disable-coccinelle], [Disable coccinelle QA steps during make check]),[enable_coccinelle="$enableval"],[enable_coccinelle=yes])
    AS_IF([test "x$enable_coccinelle" = "xyes"], [
        AC_PATH_PROG(HAVE_COCCINELLE_CONFIG, spatch, "no")
        if test "$HAVE_COCCINELLE_CONFIG" = "no"; then
            enable_coccinelle=no
        fi
    ])
    AM_CONDITIONAL([HAVE_COCCINELLE], [test "x$enable_coccinelle" != "xno"])

  # disable detection
    AC_ARG_ENABLE(detection,
           AS_HELP_STRING([--disable-detection], [Disable Detection Modules]), [enable_detection="$enableval"],[enable_detection=yes])
    AS_IF([test "x$enable_detection" = "xno"], [
        AC_DEFINE([HAVE_DETECT_DISABLED], [1], [Detection is disabled])
    ])

  # Tilera PCIE logging
    AM_CONDITIONAL([BUILD_PCIE_LOGGING], [test ! -z "$TILERA_ROOT"])

# libraries

    AC_MSG_CHECKING([for Mpipe])
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([[#include <gxio/mpipe.h>]])],
        [
        AC_MSG_RESULT([yes])
        AC_DEFINE([HAVE_MPIPE],[1],[mPIPE support is available])
        LDFLAGS="$LDFLAGS -lgxpci -lgxio -ltmc"
        ],
        [AC_MSG_RESULT([no])])

  #libpcre
    AC_ARG_WITH(libpcre_includes,
            [  --with-libpcre-includes=DIR  libpcre include directory],
            [with_libpcre_includes="$withval"],[with_libpcre_includes=no])
    AC_ARG_WITH(libpcre_libraries,
            [  --with-libpcre-libraries=DIR    libpcre library directory],
            [with_libpcre_libraries="$withval"],[with_libpcre_libraries="no"])

    if test "$with_libpcre_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libpcre_includes}"
    fi
    AC_CHECK_HEADER(pcre.h,,[AC_ERROR(pcre.h not found ...)])

    if test "$with_libpcre_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_libpcre_libraries}"
    fi
    PCRE=""
    AC_CHECK_LIB(pcre, pcre_get_substring,, PCRE="no")
    if test "$PCRE" = "no"; then
        echo
        echo "   ERROR!  pcre library not found, go get it"
        echo "   from www.pcre.org."
        echo
        exit 1
    fi

    # libpcre 8.35 (especially on debian) has a known issue that results in segfaults
    # see https://redmine.openinfosecfoundation.org/issues/1693
    if test "$with_libpcre_libraries" = "no"; then
        PKG_CHECK_MODULES(LIBPCREVERSION, [libpcre = 8.35],[libpcre_buggy_found="yes"],[libprce_buggy_found="no"])
        if test "$libpcre_buggy_found" = "yes"; then
            echo
            echo "   Warning! vulnerable libpcre version 8.35 found"
            echo "   This version has a known issue that could result in segfaults"
            echo "   please upgrade to a newer version of pcre which you can get from"
            echo "   www.pcre.org. For more information, see issue #1693"
            echo
            echo "   Continuing for now with JIT disabled..."
            echo
        fi
    fi

    # To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
    # see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
    PCRE=""
    TMPLIBS="${LIBS}"
    AC_CHECK_LIB(pcre, pcre_dfa_exec,, PCRE="no")
    if test "$PCRE" = "no"; then
        echo
        echo "   ERROR!  pcre library was found but version was < 6.0"
        echo "   please upgrade to a newer version of pcre which you can get from"
        echo "   www.pcre.org."
        echo
        exit 1
    fi
    LIBS="${TMPLIBS}"

    AC_TRY_COMPILE([ #include <pcre.h> ],
        [ int eo = 0; eo |= PCRE_EXTRA_MATCH_LIMIT_RECURSION; ],
        [ pcre_match_limit_recursion_available=yes ], [:]
    )
    if test "$pcre_match_limit_recursion_available" != "yes"; then
        echo
        echo "   Warning! pcre extra opt PCRE_EXTRA_MATCH_LIMIT_RECURSION not found"
        echo "   This could lead to potential DoS please upgrade to pcre >= 6.5"
        echo "   from www.pcre.org."
        echo "   Continuing for now...."
        echo
        AC_DEFINE([NO_PCRE_MATCH_RLIMIT],[1],[Pcre PCRE_EXTRA_MATCH_LIMIT_RECURSION not available])
    fi

    TMPCFLAGS="${CFLAGS}"
    CFLAGS="-O0 -g -Werror -Wall"
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [ pcre_extra *extra = NULL; pcre_free_study(extra); ],
        [ AC_DEFINE([HAVE_PCRE_FREE_STUDY], [1], [Pcre pcre_free_study supported])], [:]
    )
    CFLAGS="${TMPCFLAGS}"

    #enable support for PCRE-jit available since pcre-8.20
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_TRY_COMPILE([ #include <pcre.h> ],
        [
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ],
        [ pcre_jit_available=yes ], [ pcre_jit_available=no ]
        )

    case $host in
        *powerpc64*)
            PKG_CHECK_MODULES(LIBPCREVERSION, [libpcre = 8.39],[libpcre_ppc64_buggy_found1="yes"],[libprce_ppc64_buggy_found1="no"])
            PKG_CHECK_MODULES(LIBPCREVERSION, [libpcre = 8.40],[libpcre_ppc64_buggy_found2="yes"],[libprce_ppc64_buggy_found2="no"])

            if test "$libprce_ppc64_buggy_found1" = "yes" || test "$libprce_ppc64_buggy_found2"; then
                # on powerpc64, both gcc and clang lead to SIGILL in
                # unittests when jit is enabled.
                pcre_jit_available="no, pcre 8.39/8.40 jit disabled for powerpc64"
            fi
        ;;
        *)
            # bug 1693, libpcre 8.35 is broken and debian jessie is still using that
            if test "$libpcre_buggy_found" = "yes"; then
                pcre_jit_available="no, libpcre 8.35 blacklisted"
            fi
        ;;
    esac

    if test "x$pcre_jit_available" = "xyes"; then
       AC_MSG_RESULT(yes)
       AC_DEFINE([PCRE_HAVE_JIT], [1], [Pcre with JIT compiler support enabled])

       AC_MSG_CHECKING(for PCRE JIT support usability)
       AC_TRY_COMPILE([ #include <pcre.h> ],
           [
           const char* regexstr = "(a|b|c|d)";
           pcre *re;
           const char *error;
           pcre_extra *extra;
           int err_offset;
           re = pcre_compile(regexstr,0, &error, &err_offset,NULL);
           extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ],
           [ pcre_jit_works=yes ], [:]
       )
       if test "x$pcre_jit_works" != "xyes"; then
           AC_MSG_RESULT(no)
           echo
           echo "   PCRE JIT support detection worked but testing it failed"
           echo "   something odd is going on, please file a bug report."
           echo
           exit 1
       else
           AC_MSG_RESULT(yes)
       fi
    else
        AC_MSG_RESULT(no)
    fi

  # libhs
    enable_hyperscan="no"

    # Try pkg-config first:
    PKG_CHECK_MODULES([libhs], libhs,, [with_pkgconfig_libhs=no])
    if test "$with_pkgconfig_libhs" != "no"; then
        CPPFLAGS="${CPPFLAGS} ${libhs_CFLAGS}"
        LIBS="${LIBS} ${libhs_LIBS}"
    fi

    AC_ARG_WITH(libhs_includes,
            [  --with-libhs-includes=DIR  libhs include directory],
            [with_libhs_includes="$withval"],[with_libhs_includes=no])
    AC_ARG_WITH(libhs_libraries,
            [  --with-libhs-libraries=DIR    libhs library directory],
            [with_libhs_libraries="$withval"],[with_libhs_libraries="no"])

    if test "$with_libhs_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libhs_includes}"
    fi
    AC_CHECK_HEADER(hs.h,HYPERSCAN="yes",HYPERSCAN="no")
    if test "$HYPERSCAN" = "yes"; then
        if test "$with_libhs_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libhs_libraries}"
        fi

        AC_CHECK_LIB(hs,hs_compile,,HYPERSCAN="no")
        AC_CHECK_FUNCS(hs_valid_platform)
        enable_hyperscan="yes"
        if test "$HYPERSCAN" = "no"; then
            echo
            echo "   Hyperscan headers are present, but link test failed."
            echo "   Check that you have a shared library and C++ linkage available."
            echo
            enable_hyperscan="no"
        fi
    fi
    AS_IF([test "x$enable_hyperscan" = "xyes"], [AC_DEFINE([BUILD_HYPERSCAN], [1], [Intel Hyperscan support enabled])])

  # libyaml
    AC_ARG_WITH(libyaml_includes,
            [  --with-libyaml-includes=DIR  libyaml include directory],
            [with_libyaml_includes="$withval"],[with_libyaml_includes=no])
    AC_ARG_WITH(libyaml_libraries,
            [  --with-libyaml-libraries=DIR    libyaml library directory],
            [with_libyaml_libraries="$withval"],[with_libyaml_libraries="no"])

    if test "$with_libyaml_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libyaml_includes}"
    fi

    AC_CHECK_HEADER(yaml.h,,LIBYAML="no")

    if test "$with_libyaml_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_libyaml_libraries}"
    fi

    LIBYAML=""
    AC_CHECK_LIB(yaml,yaml_parser_initialize,,LIBYAML="no")

    if test "$LIBYAML" = "no"; then
        echo
        echo "   ERROR!  libyaml library not found, go get it"
        echo "   from http://pyyaml.org/wiki/LibYAML "
        echo "   or your distribution:"
        echo
        echo "   Ubuntu: apt-get install libyaml-dev"
        echo "   Fedora: yum install libyaml-devel"
        echo
        exit 1
    fi

  # libpthread
    AC_ARG_WITH(libpthread_includes,
            [  --with-libpthread-includes=DIR  libpthread include directory],
            [with_libpthread_includes="$withval"],[with_libpthread_includes=no])
    AC_ARG_WITH(libpthread_libraries,
            [  --with-libpthread-libraries=DIR    libpthread library directory],
            [with_libpthread_libraries="$withval"],[with_libpthread_libraries="no"])

    if test "$with_libpthread_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libpthread_includes}"
    fi

    dnl AC_CHECK_HEADER(pthread.h,,[AC_ERROR(pthread.h not found ...)])

    if test "$with_libpthread_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libpthread_libraries}"
    fi

    PTHREAD=""
    AC_CHECK_LIB(pthread, pthread_create,, PTHREAD="no")

    if test "$PTHREAD" = "no"; then
        echo
        echo "   ERROR! libpthread library not found, glibc problem?"
        echo
        exit 1
    fi

  # libjansson
    enable_jansson="no"
    AC_ARG_WITH(libjansson_includes,
            [  --with-libjansson-includes=DIR  libjansson include directory],
            [with_libjansson_includes="$withval"],[with_libjansson_includes=no])
    AC_ARG_WITH(libjansson_libraries,
            [  --with-libjansson-libraries=DIR    libjansson library directory],
            [with_libjansson_libraries="$withval"],[with_libjansson_libraries="no"])

    if test "$with_libjansson_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libjansson_includes}"
    fi

    enable_jansson="no"
    enable_unixsocket="no"

    AC_ARG_ENABLE(unix-socket,
           AS_HELP_STRING([--enable-unix-socket], [Enable unix socket [default=test]]),[enable_unixsocket="$enableval"],[enable_unixsocket=test])

    AC_CHECK_HEADER(jansson.h,JANSSON="yes",JANSSON="no")
    if test "$JANSSON" = "yes"; then
        if test "$with_libjansson_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libjansson_libraries}"
        fi

	    AC_CHECK_LIB(jansson, json_dump_callback,, JANSSON="no")
        enable_jansson="yes"
        if test "$JANSSON" = "no"; then
            echo
            echo "   Jansson >= 2.2 is required for features like unix socket"
            echo "   Go get it from your distribution or from:"
            echo "     http://www.digip.org/jansson/"
            echo
            if test "x$enable_unixsocket" = "xyes"; then
                exit 1
            fi
            enable_unixsocket="no"
            enable_jansson="no"
        else
            case $host in
                *-*-mingw32*)
                    ;;
                *-*-cygwin)
                    ;;
                *)
                    if test "x$enable_unixsocket" = "xtest"; then
                        enable_unixsocket="yes"
                    fi
                    ;;
            esac
        fi
    else
        if test "x$enable_unixsocket" = "xyes"; then
            echo
            echo "   Jansson >= 2.2 is required for features like unix socket"
            echo "   Go get it from your distribution or from:"
            echo "     http://www.digip.org/jansson/"
            echo
            exit 1
        fi
        enable_unixsocket="no"
    fi

    AS_IF([test "x$enable_unixsocket" = "xyes"], [AC_DEFINE([BUILD_UNIX_SOCKET], [1], [Unix socket support enabled])])
    e_enable_evelog=$enable_jansson

    AC_ARG_ENABLE(nflog,
            AS_HELP_STRING([--enable-nflog],[Enable libnetfilter_log support]),
                           [ enable_nflog="yes"],
                           [ enable_nflog="no"])
    AC_ARG_ENABLE(nfqueue,
           AS_HELP_STRING([--enable-nfqueue], [Enable NFQUEUE support for inline IDP]),[enable_nfqueue=yes],[enable_nfqueue=no])
    if test "$enable_nfqueue" != "no"; then
        PKG_CHECK_MODULES([libnetfilter_queue], [libnetfilter_queue], [enable_nfqueue=yes], [enable_nfqueue=no])
        CPPFLAGS="${CPPFLAGS} ${libnetfilter_queue_CFLAGS}"
    fi

    if test "x$enable_nflog" = "xyes" || test  "x$enable_nfqueue" = "xyes"; then
  # libnfnetlink
        case $host in
        *-*-mingw32*)
            ;;
        *)
            AC_ARG_WITH(libnfnetlink_includes,
                    [  --with-libnfnetlink-includes=DIR  libnfnetlink include directory],
                    [with_libnfnetlink_includes="$withval"],[with_libnfnetlink_includes=no])
            AC_ARG_WITH(libnfnetlink_libraries,
                    [  --with-libnfnetlink-libraries=DIR    libnfnetlink library directory],
                    [with_libnfnetlink_libraries="$withval"],[with_libnfnetlink_libraries="no"])

            if test "$with_libnfnetlink_includes" != "no"; then
                CPPFLAGS="${CPPFLAGS} -I${with_libnfnetlink_includes}"
            fi

            if test "$with_libnfnetlink_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libnfnetlink_libraries}"
            fi

            NFNL=""
            AC_CHECK_LIB(nfnetlink, nfnl_fd,, NFNL="no")

            if test "$NFNL" = "no"; then
                echo
                echo "   ERROR!  nfnetlink library not found, go get it"
                echo "   from www.netfilter.org."
                echo "   we automatically append libnetfilter_queue/ when searching"
                echo "   for headers etc. when the --with-libnfnetlink-includes directive"
                echo "   is used"
                echo
            fi
            ;;
        esac
    fi

    # enable support for NFQUEUE
    if test "x$enable_nfqueue" = "xyes"; then
        AC_DEFINE_UNQUOTED([NFQ],[1],[Enable Linux Netfilter NFQUEUE support for inline IDP])

      #libnetfilter_queue
        AC_ARG_WITH(libnetfilter_queue_includes,
            [  --with-libnetfilter_queue-includes=DIR  libnetfilter_queue include directory],
            [with_libnetfilter_queue_includes="$withval"],[with_libnetfilter_queue_includes=no])
        AC_ARG_WITH(libnetfilter_queue_libraries,
            [  --with-libnetfilter_queue-libraries=DIR    libnetfilter_queue library directory],
            [with_libnetfilter_queue_libraries="$withval"],[with_libnetfilter_queue_libraries="no"])

        if test "$with_libnetfilter_queue_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_queue_includes}"
        fi

        AC_CHECK_HEADER(libnetfilter_queue/libnetfilter_queue.h,,[AC_ERROR(libnetfilter_queue/libnetfilter_queue.h not found ...)])

        if test "$with_libnetfilter_queue_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_queue_libraries}"
        fi

        NFQ=""
        AC_CHECK_LIB(netfilter_queue, nfq_open,, NFQ="no",)
        AC_CHECK_LIB([netfilter_queue], [nfq_set_queue_maxlen],AC_DEFINE_UNQUOTED([HAVE_NFQ_MAXLEN],[1],[Found queue max length support in netfilter_queue]) ,,[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_verdict2],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_VERDICT2],[1],[Found nfq_set_verdict2 function in netfilter_queue]) ,,[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_queue_flags],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_QUEUE_FLAGS],[1],[Found nfq_set_queue_flags function in netfilter_queue]) ,,[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_verdict_batch],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_VERDICT_BATCH],[1],[Found nfq_set_verdict_batch function in netfilter_queue]) ,,[-lnfnetlink])

        # check if the argument to nfq_get_payload is signed or unsigned
        AC_MSG_CHECKING([for signed nfq_get_payload payload argument])
        STORECFLAGS="${CFLAGS}"
        if test `basename $CC` = "clang"; then
            CFLAGS="${CFLAGS} -Werror=incompatible-pointer-types"
        else
            CFLAGS="${CFLAGS} -Werror"
        fi
        AC_COMPILE_IFELSE(
            [AC_LANG_PROGRAM(
                [
                    #include <stdio.h>
                    #include <libnetfilter_queue/libnetfilter_queue.h>
                ],
                [
                    char *pktdata;
                    nfq_get_payload(NULL, &pktdata);
                ])],
            [libnetfilter_queue_nfq_get_payload_signed="yes"],
            [libnetfilter_queue_nfq_get_payload_signed="no"])
        AC_MSG_RESULT($libnetfilter_queue_nfq_get_payload_signed)
        if test "x$libnetfilter_queue_nfq_get_payload_signed" = "xyes"; then
            AC_DEFINE([NFQ_GET_PAYLOAD_SIGNED], [1], [For signed version of nfq_get_payload])
        fi
        CFLAGS="${STORECFLAGS}"

        if test "$NFQ" = "no"; then
            echo
            echo "   ERROR!  libnetfilter_queue library not found, go get it"
            echo "   from www.netfilter.org."
            echo "   we automatically append libnetfilter_queue/ when searching"
            echo "   for headers etc. when the --with-libnfq-includes directive"
            echo "   is used"
            echo
            exit 1
        fi
    fi

  # libnetfilter_log
    AC_ARG_WITH(libnetfilter_log_includes,
            [  --with-libnetfilter_log-includes=DIR  libnetfilter_log include directory],
            [with_libnetfilter_log_includes="$withval"],[with_libnetfilter_log_includes="no"])
    AC_ARG_WITH(libnetfilter_log_libraries,
            [  --with-libnetfilter_log-libraries=DIR    libnetfilter_log library directory],
            [with_libnetfilter_log_libraries="$withval"],[with_libnetfilter_log_libraries="no"])

    if test "$enable_nflog" = "yes"; then
        if test "$with_libnetfilter_log_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libnetfilter_log_includes}"
        fi

        AC_CHECK_HEADER(libnetfilter_log/libnetfilter_log.h,,[AC_ERROR(libnetfilter_log.h not found ...)])

        if test "$with_libnetfilter_log_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libnetfilter_log_libraries}"
        fi

        NFLOG=""
        AC_CHECK_LIB(netfilter_log, nflog_open,, NFLOG="no")

        if test "$NFLOG" = "no"; then
            echo
            echo "   ERROR!  libnetfilter_log library not found, go get it"
            echo "   from http://www.netfilter.org."
            echo
            exit 1
        else
            AC_DEFINE([HAVE_NFLOG],[1],[nflog available])
            enable_nflog="yes"
        fi
    fi

  # prelude
    AC_ARG_ENABLE(prelude,
            AS_HELP_STRING([--enable-prelude], [Enable Prelude support for alerts]),,[enable_prelude=no])
    # Prelude doesn't work with -Werror
    STORECFLAGS="${CFLAGS}"
    CFLAGS="${CFLAGS} -Wno-error=unused-result"

    AS_IF([test "x$enable_prelude" = "xyes"], [
        AM_PATH_LIBPRELUDE(0.9.9, , AC_MSG_ERROR(Cannot find libprelude: Is libprelude-config in the path?), no)
        if test "x${LIBPRELUDE_CFLAGS}" != "x"; then
            CPPFLAGS="${CPPFLAGS} ${LIBPRELUDE_CFLAGS}"
        fi

        if test "x${LIBPRELUDE_LDFLAGS}" != "x"; then
            LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LDFLAGS}"
        fi

        if test "x${LIBPRELUDE_LIBS}" != "x"; then
            LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LIBS}"
        fi
        AC_DEFINE([PRELUDE], [1], [Libprelude support enabled])
    ])
    CFLAGS="${STORECFLAGS}"


  # libnet
    AC_ARG_WITH(libnet_includes,
            [  --with-libnet-includes=DIR     libnet include directory],
            [with_libnet_includes="$withval"],[with_libnet_includes="no"])

    AC_ARG_WITH(libnet_libraries,
            [  --with-libnet-libraries=DIR    libnet library directory],
            [with_libnet_libraries="$withval"],[with_libnet_libraries="no"])

    if test "x$with_libnet_includes" != "xno"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libnet_includes}"
        libnet_dir="${with_libnet_includes}"
    else
        libnet_dir="/usr/include /usr/local/include /usr/local/include/libnet11 /opt/local/include /usr/local/include/libnet-1.1"
    fi

    if test "x$with_libnet_libraries" != "xno"; then
        LDFLAGS="${LDFLAGS} -L${with_libnet_libraries}"
    fi

    LIBNET_DETECT_FAIL="no"
    LIBNET_INC_DIR=""

    for i in $libnet_dir; do
    if test -r "$i/libnet.h"; then
        LIBNET_INC_DIR="$i"
    fi
    done

    enable_libnet="no"
    AC_MSG_CHECKING(for libnet.h version 1.1.x)
    if test "$LIBNET_INC_DIR" != ""; then
        LIBNET_VER=`grep LIBNET_VERSION $LIBNET_INC_DIR/libnet.h | grep '1.[[12]]' | sed 's/[[^"]]*"\([[^"]]*\).*/\1/'`

        if test -z "$LIBNET_VER" ; then
            AC_MSG_RESULT(no)
        else
            AC_MSG_RESULT(yes)
        fi

        #CentOS, Fedora, Ubuntu-LTS, Ubuntu all set defines to the same values. libnet-config seems
        #to have been depreciated but all distro's seem to include it as part of the package.
        if test "$LIBNET_DETECT_FAIL" = "no"; then
            LLIBNET=""
            AC_CHECK_LIB(net, libnet_write,, LLIBNET="no")
            if test "$LLIBNET" != "no"; then
                AC_DEFINE([HAVE_LIBNET11],[1],(libnet 1.1 available))
                AC_DEFINE([_DEFAULT_SOURCE],[1],(default source))
                AC_DEFINE([_BSD_SOURCE],[1],(bsd source))
                AC_DEFINE([__BSD_SOURCE],[1],(bsd source))
                AC_DEFINE([__FAVOR_BSD],[1],(favor bsd))
                AC_DEFINE([HAVE_NET_ETHERNET_H],[1],(ethernet.h))
                enable_libnet="yes"
            fi

            # see if we have the patched libnet 1.1
            # http://www.inliniac.net/blog/2007/10/16/libnet-11-ipv6-fixes-and-additions.html
            #
            # To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
            # see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
            if test "$enable_libnet" = "yes"; then
                LLIBNET=""
                TMPLIBS="${LIBS}"
                AC_CHECK_LIB(net, libnet_build_icmpv6_unreach,, LLIBNET="no")
                if test "$LLIBNET" != "no"; then
                    AC_DEFINE([HAVE_LIBNET_ICMPV6_UNREACH],[1],(libnet_build_icmpv6_unreach available))
                fi
                LIBS="${TMPLIBS}"
            fi

            # See if we have libnet 1.1.6 or newer - these versions handle capabilities correctly
            # Some patched 1.1.4 versions are also good, but it's not guaranteed for all distros.
            #
            # Details: https://bugzilla.redhat.com/show_bug.cgi?id=589770
            AS_VERSION_COMPARE([LIBNET_VER], [1.1.6],
                [],
                [AC_DEFINE([HAVE_LIBNET_CAPABILITIES],[1], (libnet_have_capabilities_patch))],
                [AC_DEFINE([HAVE_LIBNET_CAPABILITIES],[1], (libnet_have_capabilities_patch))])


            # check if the argument to libnet_init is char* or const char*
            AC_MSG_CHECKING([libnet_init dev type])
            STORECFLAGS="${CFLAGS}"
            if test `basename $CC` = "clang"; then
                CFLAGS="${CFLAGS} -Werror=incompatible-pointer-types"
            else
                CFLAGS="${CFLAGS} -Werror"
            fi
            AC_COMPILE_IFELSE(
                [AC_LANG_PROGRAM(
                    [
                    #include <stdio.h>
                    #include <libnet.h>
                    ],
                    [[
                    const char dev[32] = "";
                    char ebuf[LIBNET_ERRBUF_SIZE];
                    (void)libnet_init(LIBNET_LINK, dev, ebuf);
                    ]])],
                [libnet_init_const="yes"],
                [libnet_init_const="no"])
            AC_MSG_RESULT($libnet_init_const)
            if test "x$libnet_init_const" = "xyes"; then
                AC_DEFINE([HAVE_LIBNET_INIT_CONST], [1], [libnet_init takes const argument])
            fi
            CFLAGS="${STORECFLAGS}"
        fi
    else
        AC_MSG_RESULT(no)
    fi

  # libpcap
    AC_ARG_WITH(libpcap_includes,
            [  --with-libpcap-includes=DIR  libpcap include directory],
            [with_libpcap_includes="$withval"],[with_libpcap_includes=no])
    AC_ARG_WITH(libpcap_libraries,
            [  --with-libpcap-libraries=DIR    libpcap library directory],
            [with_libpcap_libraries="$withval"],[with_libpcap_libraries="no"])

    if test "$with_libpcap_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
    fi

    AC_CHECK_HEADER(pcap.h,,[AC_ERROR(pcap.h not found ...)])

    if test "$with_libpcap_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
    fi
    AC_CHECK_HEADERS([pcap.h pcap/pcap.h pcap/bpf.h])

    LIBPCAP=""
    AC_CHECK_LIB(${PCAP_LIB_NAME}, pcap_open_live,, LIBPCAP="no")
    if test "$LIBPCAP" = "no"; then
        echo
        echo "   ERROR!  libpcap library not found, go get it"
        echo "   from http://www.tcpdump.org or your distribution:"
        echo
        echo "   Ubuntu: apt-get install libpcap-dev"
        echo "   Fedora: yum install libpcap-devel"
        echo
        exit 1
    fi

    # pcap_activate and pcap_create only exists in libpcap >= 1.0
    LIBPCAPVTEST=""
    #To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
    #see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
    TMPLIBS="${LIBS}"
    AC_CHECK_LIB(${PCAP_LIB_NAME}, pcap_activate,, LPCAPVTEST="no")
    if test "$LPCAPVTEST" = "no"; then
        echo
        echo "   ERROR!  libpcap library too old, need at least 1+, "
        echo "   go get it from http://www.tcpdump.org or your distribution:"
        echo
        echo "   Ubuntu: apt-get install libpcap-dev"
        echo "   Fedora: yum install libpcap-devel"
        echo
        exit 1
    fi
    AC_PATH_PROG(HAVE_PCAP_CONFIG, pcap-config, "no")
    if test "$HAVE_PCAP_CONFIG" = "no" -o "$cross_compiling" = "yes"; then
        AC_MSG_RESULT(no pcap-config is use)
    else
        PCAP_CFLAGS="$(pcap-config --defines) $(pcap-config --cflags)"
        AC_SUBST(PCAP_CFLAGS)
    fi
    LIBS="${TMPLIBS}"

    #Appears as if pcap_set_buffer_size is linux only?
    LIBPCAPSBUFF=""
    #To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
    #see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
    TMPLIBS="${LIBS}"
    AC_CHECK_LIB(${PCAP_LIB_NAME}, pcap_set_buffer_size,, LPCAPSBUFF="no")
    if test "$LPCAPSBUFF" != "no"; then
        AC_DEFINE([HAVE_PCAP_SET_BUFF],[1],(libpcap has pcap_set_buffer_size function))
    fi
    LIBS="${TMPLIBS}"

  # libpfring
    # libpfring (currently only supported for libpcap enabled pfring)
    # Error on the side of caution. If libpfring enabled pcap is being used and we don't link against -lpfring compilation will fail.
    AC_ARG_ENABLE(pfring,
           AS_HELP_STRING([--enable-pfring], [Enable Native PF_RING support]),,[enable_pfring=no])
    AS_IF([test "x$enable_pfring" = "xyes"], [
        AC_DEFINE([HAVE_PFRING],[1],(PF_RING support enabled))

        #We have to set CFLAGS for AC_TRY_COMPILE as it doesn't pay attention to CPPFLAGS
        AC_ARG_WITH(libpfring_includes,
                [  --with-libpfring-includes=DIR  libpfring include directory],
                [with_libpfring_includes="$withval"],[with_libpfring_includes=no])
        AC_ARG_WITH(libpfring_libraries,
                [  --with-libpfring-libraries=DIR    libpfring library directory],
                [with_libpfring_libraries="$withval"],[with_libpfring_libraries="no"])

        if test "$with_libpfring_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libpfring_includes}"
        fi

        if test "$with_libpfring_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libpfring_libraries}"
        fi

        LIBPFRING=""
        AC_CHECK_LIB(pfring, pfring_open,, LIBPFRING="no", [-lpcap])
        if test "$LIBPFRING" != "no"; then
            STORECFLAGS="${CFLAGS}"
            CFLAGS="${CFLAGS} -Werror"
            AC_COMPILE_IFELSE(
                [AC_LANG_PROGRAM(
                    [
                    #include <pfring.h>
                    ],
                    [
                    pfring_recv_chunk(NULL, NULL, 0, 0);
                    ])],
                [pfring_recv_chunk="yes"],
                [pfring_recv_chunk="no"])
            CFLAGS="${STORECFLAGS}"
            if test "x$pfring_recv_chunk" != "xyes"; then
                if test "x$enable_pfring" = "xyes"; then
                echo
                echo "   ERROR! --enable-pfring was passed but the library version is < 6, go get it"
                echo "   from http://www.ntop.org/products/pf_ring/"
                echo
                exit 1
                fi
            fi
        else
            if test "x$enable_pfring" = "xyes"; then
            echo
            echo "   ERROR! --enable-pfring was passed but the library was not found, go get it"
            echo "   from http://www.ntop.org/products/pf_ring/"
            echo
            exit 1
            fi
        fi
    ])

  # AF_PACKET support
    AC_ARG_ENABLE(af-packet,
           AS_HELP_STRING([--enable-af-packet], [Enable AF_PACKET support [default=yes]]),
                        ,[enable_af_packet=yes])
    AS_IF([test "x$enable_af_packet" = "xyes"], [
        AC_CHECK_DECL([TPACKET_V2],
            AC_DEFINE([HAVE_AF_PACKET],[1],[AF_PACKET support is available]),
            [enable_af_packet="no"],
            [[#include <sys/socket.h>
              #include <linux/if_packet.h>]])
        AC_CHECK_DECL([PACKET_FANOUT_QM],
            AC_DEFINE([HAVE_PACKET_FANOUT],[1],[Recent packet fanout support is available]),
            [],
            [[#include <linux/if_packet.h>]])
        AC_CHECK_DECL([TPACKET_V3],
            AC_DEFINE([HAVE_TPACKET_V3],[1],[AF_PACKET tpcket_v3 support is available]),
            [],
            [[#include <sys/socket.h>
              #include <linux/if_packet.h>]])
        AC_CHECK_DECL([SOF_TIMESTAMPING_RAW_HARDWARE],
            AC_DEFINE([HAVE_HW_TIMESTAMPING],[1],[Hardware timestamping support is available]),
            [],
            [[#include <linux/net_tstamp.h>]])
    ])

  # Netmap support
    AC_ARG_ENABLE(netmap,
            AS_HELP_STRING([--enable-netmap], [Enable Netmap support]),,[enable_netmap=no])
    AC_ARG_WITH(netmap_includes,
            [  --with-netmap-includes=DIR netmap include directory],
            [with_netmap_includes="$withval"],[with_netmap_includes=no])

    AS_IF([test "x$enable_netmap" = "xyes"], [
        AC_DEFINE([HAVE_NETMAP],[1],(NETMAP support enabled))

        if test "$with_netmap_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_netmap_includes}"
        fi

        AC_CHECK_HEADER(net/netmap_user.h,,[AC_ERROR(net/netmap_user.h not found ...)],)
  ])

  # libhtp
    AC_ARG_ENABLE(non-bundled-htp,
           AS_HELP_STRING([--enable-non-bundled-htp], [Enable the use of an already installed version of htp]),,[enable_non_bundled_htp=no])
    AS_IF([test "x$enable_non_bundled_htp" = "xyes"], [
        PKG_CHECK_MODULES([libhtp], htp,, [with_pkgconfig_htp=no])
        if test "$with_pkgconfig_htp" != "no"; then
            CPPFLAGS="${CPPFLAGS} ${libhtp_CFLAGS}"
            LIBS="${LIBS} ${libhtp_LIBS}"
        fi

        AC_ARG_WITH(libhtp_includes,
                [  --with-libhtp-includes=DIR  libhtp include directory],
                [with_libhtp_includes="$withval"],[with_libhtp_includes=no])
        AC_ARG_WITH(libhtp_libraries,
                [  --with-libhtp-libraries=DIR    libhtp library directory],
                [with_libhtp_libraries="$withval"],[with_libhtp_libraries="no"])

        if test "$with_libhtp_includes" != "no"; then
            CPPFLAGS="-I${with_libhtp_includes} ${CPPFLAGS}"
        fi

        if test "$with_libhtp_libraries" != "no"; then
            LDFLAGS="${LDFLAGS} -L${with_libhtp_libraries}"
        fi

        AC_CHECK_HEADER(htp/htp.h,,[AC_ERROR(htp/htp.h not found ...)])

        LIBHTP=""
        AC_CHECK_LIB(htp, htp_conn_create,, LIBHTP="no")
        if test "$LIBHTP" = "no"; then
            echo
            echo "   ERROR! libhtp library not found"
            echo
            exit 1
        fi
        PKG_CHECK_MODULES(LIBHTPMINVERSION, [htp >= 0.5.20],[libhtp_minver_found="yes"],[libhtp_minver_found="no"])
        if test "$libhtp_minver_found" = "no"; then
            PKG_CHECK_MODULES(LIBHTPDEVVERSION, [htp = 0.5.X],[libhtp_devver_found="yes"],[libhtp_devver_found="no"])
            if test "$libhtp_devver_found" = "no"; then
                echo
                echo "   ERROR! libhtp was found but it is neither >= 0.5.20, nor the dev 0.5.X"
                echo
                exit 1
            fi
        fi

        AC_CHECK_LIB([htp], [htp_config_register_request_uri_normalize],AC_DEFINE_UNQUOTED([HAVE_HTP_URI_NORMALIZE_HOOK],[1],[Found htp_config_register_request_uri_normalize function in libhtp]) ,,[-lhtp])
        # check for htp_tx_get_response_headers_raw
        AC_CHECK_LIB([htp], [htp_tx_get_response_headers_raw],AC_DEFINE_UNQUOTED([HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW],[1],[Found htp_tx_get_response_headers_raw in libhtp]) ,,[-lhtp])
        AC_CHECK_LIB([htp], [htp_decode_query_inplace],AC_DEFINE_UNQUOTED([HAVE_HTP_DECODE_QUERY_INPLACE],[1],[Found htp_decode_query_inplace function in libhtp]) ,,[-lhtp])
        AC_CHECK_LIB([htp], [htp_config_set_response_decompression_layer_limit],AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT],[1],[Found htp_config_set_response_decompression_layer_limit function in libhtp]) ,,[-lhtp])
        AC_EGREP_HEADER(htp_config_set_path_decode_u_encoding, htp/htp.h, AC_DEFINE_UNQUOTED([HAVE_HTP_SET_PATH_DECODE_U_ENCODING],[1],[Found usable htp_config_set_path_decode_u_encoding function in libhtp]) )
    ])

    if test "x$enable_non_bundled_htp" = "xno"; then
        # test if we have a bundled htp
        if test -d "$srcdir/libhtp"; then
            AC_CONFIG_SUBDIRS([libhtp])
            HTP_DIR="libhtp"
            AC_SUBST(HTP_DIR)
            HTP_LDADD="../libhtp/htp/libhtp.la"
            AC_SUBST(HTP_LDADD)
            # make sure libhtp is added to the includes
            CPPFLAGS="-I\${srcdir}/../libhtp/ ${CPPFLAGS}"

            AC_CHECK_HEADER(iconv.h,,[AC_ERROR(iconv.h not found ...)])
            AC_CHECK_LIB(iconv, libiconv_close)
            AC_DEFINE_UNQUOTED([HAVE_HTP_URI_NORMALIZE_HOOK],[1],[Assuming htp_config_register_request_uri_normalize function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW],[1],[Assuming htp_tx_get_response_headers_raw function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_DECODE_QUERY_INPLACE],[1],[Assuming htp_decode_query_inplace function in bundled libhtp])
            # enable when libhtp has been updated
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT],[1],[Assuming htp_config_set_response_decompression_layer_limit function in bundled libhtp])
        else
            echo
            echo "  ERROR: Libhtp is not bundled. Get libhtp by doing:"
            echo "     git clone https://github.com/OISF/libhtp"
            echo "  Then re-run Suricata's autogen.sh and configure script."
            echo "  Or, if libhtp is installed in a different location,"
            echo "  pass --enable-non-bundled-htp to Suricata's configure script."
            echo "  Add --with-libhtp-includes=<dir> and --with-libhtp-libraries=<dir> if"
            echo "  libhtp is not installed in the include and library paths."
            echo
            exit 1
        fi
    fi


  # enable CUDA output
    AC_ARG_ENABLE(cuda,
           AS_HELP_STRING([--enable-cuda], [Enable experimental CUDA pattern matching]),,[enable_cuda=no])
    AS_IF([test "x$enable_cuda" = "xyes"], [
        AC_ARG_WITH(cuda_includes,
                [  --with-cuda-includes=DIR  cuda include directory],
                [with_cuda_includes="$withval"],[with_cuda_includes=no])
        AC_ARG_WITH(cuda_libraries,
                [  --with-cuda-libraries=DIR    cuda library directory],
                [with_cuda_libraries="$withval"],[with_cuda_libraries="no"])
        AC_ARG_WITH(cuda_nvcc,
                [  --with-cuda-nvcc=DIR  cuda nvcc compiler directory],
                [with_cuda_nvcc="$withval"],[with_cuda_nvcc=no])

        AC_DEFINE([__SC_CUDA_SUPPORT__],[1],(CUDA support enabled))

        if test "$with_cuda_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_cuda_includes}"
        else
            CPPFLAGS="${CPPFLAGS} -I/usr/local/cuda/include"
        fi

        if test "$with_cuda_libraries" != "no"; then
            LDFLAGS="${LDFLAGS} -L${with_cuda_libraries}"
        fi

        if test "$with_cuda_nvcc" != "no"; then
            NVCC_DIR="${with_cuda_nvcc}"
        else
            NVCC_DIR="/usr/local/cuda/bin"
        fi

        AC_CHECK_HEADER(cuda.h,,[AC_ERROR(cuda.h not found ...)])

        LIBCUDA=""
        AC_CHECK_LIB(cuda, cuArray3DCreate,, LIBCUDA="no")
        if test "$LIBCUDA" = "no"; then
            echo
            echo "   ERROR! libcuda library not found"
            echo
            exit 1
        fi

        AC_PATH_PROG([NVCC], [nvcc], no, [$PATH:$NVCC_DIR])
        if test "x$NVCC" = "xno"; then
            echo
            echo "   ERROR! CUDA nvcc compiler not found: use --with-cuda-nvcc=DIR"
            echo
            exit 1
        fi

        AC_MSG_CHECKING(for nvcc version)
        NVCCVER=`$NVCC --version | grep "release" | sed 's/.*release \(@<:@0-9@:>@\)\.\(@<:@0-9@:>@\).*/\1\2/'`
        AC_MSG_RESULT($NVCCVER)
        if test "$NVCCVER" -lt 31; then
            echo
            echo "   Warning! Your CUDA nvcc version might be outdated."
            echo "   If compilation fails try the latest CUDA toolkit from"
            echo "   www.nvidia.com/object/cuda_develop.html"
            echo
        fi

        AM_PATH_PYTHON(,, no)
        if test "x$PYTHON" = "xno"; then
            echo
            echo "   ERROR! Compiling CUDA kernels requires python."
            echo
            exit 1
        fi
    ])
    AM_CONDITIONAL([BUILD_CUDA], [test "x$enable_cuda" = "xyes"])
    AM_CONDITIONAL([__SC_CUDA_SUPPORT__], [test "x$enable_cuda" = "xyes"])


  # Check for libcap-ng
    case $host in
    *-*-linux*)
    AC_ARG_WITH(libcap_ng_includes,
            [  --with-libcap_ng-includes=DIR  libcap_ng include directory],
            [with_libcap_ng_includes="$withval"],[with_libcap_ng_includes=no])
    AC_ARG_WITH(libcap_ng_libraries,
            [  --with-libcap_ng-libraries=DIR    libcap_ng library directory],
            [with_libcap_ng_libraries="$withval"],[with_libcap_ng_libraries="no"])

    if test "$with_libcap_ng_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libcap_ng_includes}"
    fi

    if test "$with_libcap_ng_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libcap_ng_libraries}"
    fi

    AC_CHECK_HEADER(cap-ng.h,,LIBCAP_NG="no")
    if test "$LIBCAP_NG" != "no"; then
        LIBCAP_NG=""
        AC_CHECK_LIB(cap-ng,capng_clear,,LIBCAP_NG="no")
    fi

    if test "$LIBCAP_NG" != "no"; then
        AC_DEFINE([HAVE_LIBCAP_NG],[1],[Libpcap-ng support])
    fi

    if test "$LIBCAP_NG" = "no"; then
        echo
        echo "   WARNING!  libcap-ng library not found, go get it"
        echo "   from http://people.redhat.com/sgrubb/libcap-ng/"
        echo "   or your distribution:"
        echo
        echo "   Ubuntu: apt-get install libcap-ng-dev"
        echo "   Fedora: yum install libcap-ng-devel"
        echo
        echo "   Suricata will be built without support for dropping privs."
        echo
    fi
    ;;
    esac

  # Check for DAG support.
    AC_ARG_ENABLE(dag,
	        AS_HELP_STRING([--enable-dag],[Enable DAG capture]),
	        [ enable_dag=yes ],
	        [ enable_dag=no])
    AC_ARG_WITH(dag_includes,
            [  --with-dag-includes=DIR  dagapi include directory],
            [with_dag_includes="$withval"],[with_dag_includes="no"])
    AC_ARG_WITH(dag_libraries,
            [  --with-dag-libraries=DIR  dagapi library directory],
            [with_dag_libraries="$withval"],[with_dag_libraries="no"])

    if test "$enable_dag" = "yes"; then

    	if test "$with_dag_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_dag_includes}"
        fi

        if test "$with_dag_libraries" != "no"; then
            LDFLAGS="${LDFLAGS} -L${with_dag_libraries}"
        fi

        AC_CHECK_HEADER(dagapi.h,DAG="yes",DAG="no")
        if test "$DAG" != "no"; then
            DAG=""
	        AC_CHECK_LIB(dag,dag_open,,DAG="no",)
        fi

        if test "$DAG" = "no"; then
            echo
            echo "  ERROR! libdag library not found"
            echo
            exit 1
        fi

        AC_DEFINE([HAVE_DAG],[1],(Endace DAG card support enabled))
    fi

  # libnspr
    enable_nspr="no"

    # Try pkg-config first:
    PKG_CHECK_MODULES([libnspr], nspr,, [with_pkgconfig_nspr=no])
    if test "$with_pkgconfig_nspr" != "no"; then
        CPPFLAGS="${CPPFLAGS} ${libnspr_CFLAGS}"
        LIBS="${LIBS} ${libnspr_LIBS}"
    fi

    AC_ARG_WITH(libnspr_includes,
            [  --with-libnspr-includes=DIR  libnspr include directory],
            [with_libnspr_includes="$withval"],[with_libnspr_includes=no])
    AC_ARG_WITH(libnspr_libraries,
            [  --with-libnspr-libraries=DIR    libnspr library directory],
            [with_libnspr_libraries="$withval"],[with_libnspr_libraries="no"])

    if test "$with_libnspr_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libnspr_includes}"
    fi

    AC_CHECK_HEADER(nspr.h,NSPR="yes",NSPR="no")
    if test "$NSPR" = "yes"; then
        if test "$with_libnspr_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libnspr_libraries}"
        fi

        AC_CHECK_LIB(nspr4, PR_GetCurrentThread,, NSPR="no")

        if test "$NSPR" = "no"; then
            echo
            echo "   ERROR!  libnspr library not found, go get it"
            echo "   from Mozilla or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libnspr4-dev"
            echo "   Fedora: yum install nspr-devel"
            echo
            exit 1
        fi
        enable_nspr="yes"
    fi

  # libnss
    enable_nss="no"

    # Try pkg-config first:
    PKG_CHECK_MODULES([libnss], nss,, [with_pkgconfig_nss=no])
    if test "$with_pkgconfig_nss" != "no"; then
        CPPFLAGS="${CPPFLAGS} ${libnss_CFLAGS}"
        LIBS="${LIBS} ${libnss_LIBS}"
    fi

    AC_ARG_WITH(libnss_includes,
            [  --with-libnss-includes=DIR  libnss include directory],
            [with_libnss_includes="$withval"],[with_libnss_includes=no])
    AC_ARG_WITH(libnss_libraries,
            [  --with-libnss-libraries=DIR    libnss library directory],
            [with_libnss_libraries="$withval"],[with_libnss_libraries="no"])

    if test "$with_libnss_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libnss_includes}"
    fi

    AC_CHECK_HEADER(sechash.h,NSS="yes",NSS="no")
    if test "$NSS" = "yes"; then
        if test "$with_libnss_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_libnss_libraries}"
        fi

        AC_CHECK_LIB(nss3, HASH_Begin,, NSS="no")

        if test "$NSS" = "no"; then
            echo
            echo "   ERROR!  libnss library not found, go get it"
            echo "   from Mozilla or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libnss3-dev"
            echo "   Fedora: yum install nss-devel"
            echo
            exit 1
        fi

        AC_DEFINE([HAVE_NSS],[1],[libnss available for md5])
        enable_nss="yes"
    fi

  # libmagic
    enable_magic="no"
    AC_ARG_ENABLE(libmagic,
           AS_HELP_STRING([--enable-libmagic], [Enable libmagic support [default=yes]]),
                        ,[enable_magic=yes])
    if test "$enable_magic" = "yes"; then
        AC_ARG_WITH(libmagic_includes,
                [  --with-libmagic-includes=DIR  libmagic include directory],
                [with_libmagic_includes="$withval"],[with_libmagic_includes=no])
        AC_ARG_WITH(libmagic_libraries,
                [  --with-libmagic-libraries=DIR    libmagic library directory],
                [with_libmagic_libraries="$withval"],[with_libmagic_libraries="no"])

        if test "$with_libmagic_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libmagic_includes}"
        fi

        AC_CHECK_HEADER(magic.h,,MAGIC="no")
        if test "$MAGIC" != "no"; then
            MAGIC=""
            AC_CHECK_LIB(magic, magic_open,, MAGIC="no")
        fi

        if test "x$MAGIC" != "xno"; then
            if test "$with_libmagic_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libmagic_libraries}"
            fi
            AC_DEFINE([HAVE_MAGIC],[1],(Libmagic for file handling))
        else
            echo
            echo "   WARNING!  magic library not found, go get it"
            echo "   from http://www.darwinsys.com/file/ or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libmagic-dev"
            echo "   Fedora: yum install file-devel"
            echo
            enable_magic="no"
        fi
    fi

  # Napatech - Using the 3GD API
    AC_ARG_ENABLE(napatech,
                AS_HELP_STRING([--enable-napatech],[Enabled Napatech Devices]),
                [ enable_napatech=yes ],
                [ enable_napatech=no])
    AC_ARG_WITH(napatech_includes,
                [  --with-napatech-includes=DIR   napatech include directory],
                [with_napatech_includes="$withval"],[with_napatech_includes="/opt/napatech3/include"])
    AC_ARG_WITH(napatech_libraries,
                [  --with-napatech-libraries=DIR  napatech library directory],
                [with_napatech_libraries="$withval"],[with_napatech_libraries="/opt/napatech3/lib"])

    if test "$enable_napatech" = "yes"; then
        CPPFLAGS="${CPPFLAGS} -I${with_napatech_includes}"
        LDFLAGS="${LDFLAGS} -L${with_napatech_libraries} -lntapi"
        AC_CHECK_HEADER(nt.h,NAPATECH="yes",NAPATECH="no")
        if test "$NAPATECH" != "no"; then
            NAPATECH=""
            AC_CHECK_LIB(ntapi, NT_Init,NAPATECH="yes",NAPATECH="no")
        fi

        if test "$NAPATECH" = "no"; then
            echo
            echo "  ERROR! libntapi library not found"
            echo
            exit 1
        fi

        AC_DEFINE([HAVE_NAPATECH],[1],(Napatech capture card support))
    fi

  # liblua
    AC_ARG_ENABLE(lua,
	        AS_HELP_STRING([--enable-lua],[Enable Lua support]),
	        [ enable_lua="yes"],
	        [ enable_lua="no"])
    AC_ARG_ENABLE(luajit,
	        AS_HELP_STRING([--enable-luajit],[Enable Luajit support]),
	        [ enable_luajit="yes"],
	        [ enable_luajit="no"])
    if test "$enable_lua" = "yes"; then
        if test "$enable_luajit" = "yes"; then
            echo "ERROR: can't enable liblua and luajit at the same time."
            echo "For LuaJIT, just use --enable-luajit. For liblua (no jit)"
            echo "support, use just --enable-lua."
            echo "Both options will enable the Lua scripting capabilities"
            echo "in Suricata".
            echo
            exit 1
        fi
    fi

    AC_ARG_WITH(liblua_includes,
            [  --with-liblua-includes=DIR  liblua include directory],
            [with_liblua_includes="$withval"],[with_liblua_includes="no"])
    AC_ARG_WITH(liblua_libraries,
            [  --with-liblua-libraries=DIR    liblua library directory],
            [with_liblua_libraries="$withval"],[with_liblua_libraries="no"])

    if test "$enable_lua" = "yes"; then
        if test "$with_liblua_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_liblua_includes}"
        else
            # lua lua51 lua5.1 lua-5.1
            PKG_CHECK_MODULES([LUA], [lua], [LUA="yes"], [
                PKG_CHECK_MODULES([LUA], [lua5.1], [LUA="yes"], [
                    PKG_CHECK_MODULES([LUA], [lua-5.1], [LUA="yes"], [
                        PKG_CHECK_MODULES([LUA], [lua51], [LUA="yes"], [
                            LUA="no"
                        ])
                    ])
                ])
            ])
            CPPFLAGS="${CPPFLAGS} ${LUA_CFLAGS}"
        fi

        AC_CHECK_HEADER(lualib.h,LUA="yes",LUA="no")
        if test "$LUA" = "yes"; then
            if test "$with_liblua_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_liblua_libraries}"
                AC_CHECK_LIB(${LUA_LIB_NAME}, luaL_openlibs,, LUA="no")
                if test "$LUA" = "no"; then
                    echo
                    echo "   ERROR!  liblua library not found, go get it"
                    echo "   from http://lua.org/index.html or your distribution:"
                    echo
                    echo "   Ubuntu: apt-get install liblua5.1-dev"
                    echo "   CentOS/Fedora: yum install lua-devel"
                    echo
                    echo "   If you installed software in a non-standard prefix"
                    echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                    echo "   or use --with-liblua-libraries configure option."
                    echo
                    exit 1
                fi
            else
                # lua lua51 lua5.1 lua-5.1
                PKG_CHECK_MODULES([LUA], [lua], [LUA="yes"], [
                    PKG_CHECK_MODULES([LUA], [lua5.1], [LUA="yes"], [
                        PKG_CHECK_MODULES([LUA], [lua-5.1], [LUA="yes"], [
                            PKG_CHECK_MODULES([LUA], [lua51], [LUA="yes"], [
                                LUA="no"
                            ])
                        ])
                    ])
                ])
                LDFLAGS="${LDFLAGS} ${LUA_LIBS}"
            fi

            if test "$LUA" = "no"; then
                AC_CHECK_LIB(lua, luaL_openlibs,, LUA="no")
            fi

            if test "$LUA" = "yes"; then
                AC_DEFINE([HAVE_LUA],[1],[liblua available])
                enable_lua="yes"
            fi
        else
	        echo
                echo "   ERROR!  liblua headers not found, go get them"
                echo "   from http://lua.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install liblua5.1-dev"
                echo "   CentOS/Fedora: yum install lua-devel"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-liblua-includes and --with-liblua-libraries"
                echo "   configure option."
                echo
                exit 1
        fi
    fi

  # libluajit
    AC_ARG_WITH(libluajit_includes,
            [  --with-libluajit-includes=DIR  libluajit include directory],
            [with_libluajit_includes="$withval"],[with_libluajit_includes="no"])
    AC_ARG_WITH(libluajit_libraries,
            [  --with-libluajit-libraries=DIR    libluajit library directory],
            [with_libluajit_libraries="$withval"],[with_libluajit_libraries="no"])

    if test "$enable_luajit" = "yes"; then
        if test "$with_libluajit_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libluajit_includes}"
        else
            PKG_CHECK_MODULES([LUAJIT], [luajit], , LUAJIT="no")
            CPPFLAGS="${CPPFLAGS} ${LUAJIT_CFLAGS}"
        fi

        AC_CHECK_HEADER(lualib.h,LUAJIT="yes",LUAJIT="no")
        if test "$LUAJIT" = "yes"; then
            if test "$with_libluajit_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libluajit_libraries}"
            else
                PKG_CHECK_MODULES([LUAJIT], [luajit])
                LDFLAGS="${LDFLAGS} ${LUAJIT_LIBS}"
            fi

            AC_CHECK_LIB(luajit-5.1, luaL_openlibs,, LUAJIT="no")

            if test "$LUAJIT" = "no"; then
                echo
                echo "   ERROR!  libluajit library not found, go get it"
                echo "   from http://luajit.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install libluajit-5.1-dev"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-libluajit-libraries configure option."
                echo
                exit 1
            fi

            AC_DEFINE([HAVE_LUA],[1],[lua support available])
            AC_DEFINE([HAVE_LUAJIT],[1],[libluajit available])
            enable_lua="yes, through luajit"
            enable_luajit="yes"
        else
	        echo
                echo "   ERROR!  libluajit headers not found, go get them"
                echo "   from http://luajit.org/index.html or your distribution:"
                echo
                echo "   Ubuntu: apt-get install libluajit-5.1-dev"
                echo
                echo "   If you installed software in a non-standard prefix"
                echo "   consider adjusting the PKG_CONFIG_PATH environment variable"
                echo "   or use --with-libluajit-includes and --with-libluajit-libraries"
                echo "   configure option."
                echo
                exit 1
        fi
    fi

    AM_CONDITIONAL([HAVE_LUA], [test "x$enable_lua" != "xno"])

  # libgeoip
    AC_ARG_ENABLE(geoip,
	        AS_HELP_STRING([--enable-geoip],[Enable GeoIP support]),
	        [ enable_geoip="yes"],
	        [ enable_geoip="no"])
    AC_ARG_WITH(libgeoip_includes,
            [  --with-libgeoip-includes=DIR  libgeoip include directory],
            [with_libgeoip_includes="$withval"],[with_libgeoip_includes="no"])
    AC_ARG_WITH(libgeoip_libraries,
            [  --with-libgeoip-libraries=DIR    libgeoip library directory],
            [with_libgeoip_libraries="$withval"],[with_libgeoip_libraries="no"])

    if test "$enable_geoip" = "yes"; then
        if test "$with_libgeoip_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libgeoip_includes}"
        fi

        AC_CHECK_HEADER(GeoIP.h,GEOIP="yes",GEOIP="no")
        if test "$GEOIP" = "yes"; then
            if test "$with_libgeoip_libraries" != "no"; then
                LDFLAGS="${LDFLAGS} -L${with_libgeoip_libraries}"
            fi
            AC_CHECK_LIB(GeoIP, GeoIP_country_code_by_ipnum,, GEOIP="no")
        fi
        if test "$GEOIP" = "no"; then
            echo
            echo "   ERROR!  libgeoip library not found, go get it"
            echo "   from http://www.maxmind.com/en/geolite or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libgeoip-dev"
            echo "   Fedora: yum install GeoIP-devel"
            echo
            exit 1
        fi

        AC_DEFINE([HAVE_GEOIP],[1],[libgeoip available])
        enable_geoip="yes"
    fi

  # Position Independent Executable
    AC_ARG_ENABLE(pie,
                AS_HELP_STRING([--enable-pie],[Enable compiling as a position independent executable]),
                [ enable_pie="yes"],
                [ enable_pie="no"])
    if test "$enable_pie" = "yes"; then
        CPPFLAGS="${CPPFLAGS} -fPIC"
        LDFLAGS="${LDFLAGS} -pie"
    fi

#libevent includes and libraries
    AC_ARG_WITH(libevent_includes,
            [  --with-libevent-includes=DIR  libevent include directory],
            [with_libevent_includes="$withval"],[with_libevent_includes="no"])
    AC_ARG_WITH(libevent_libraries,
            [  --with-libevent-libraries=DIR    libevent library directory],
            [with_libevent_libraries="$withval"],[with_libevent_libraries="no"])

# libhiredis
    AC_ARG_ENABLE(hiredis,
	        AS_HELP_STRING([--enable-hiredis],[Enable Redis support]),
	        [ enable_hiredis="yes"],
	        [ enable_hiredis="no"])
    AC_ARG_WITH(libhiredis_includes,
            [  --with-libhiredis-includes=DIR  libhiredis include directory],
            [with_libhiredis_includes="$withval"],[with_libhiredis_includes="no"])
    AC_ARG_WITH(libhiredis_libraries,
            [  --with-libhiredis-libraries=DIR    libhiredis library directory],
            [with_libhiredis_libraries="$withval"],[with_libhiredis_libraries="no"])

    enable_hiredis_async="no"
    if test "$enable_hiredis" = "yes"; then
        if test "$with_libhiredis_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libhiredis_includes}"
        fi

        AC_CHECK_HEADER("hiredis/hiredis.h",HIREDIS="yes",HIREDIS="no")
        if test "$HIREDIS" = "yes"; then
            if test "$with_libhiredis_libraries" != "no"; then
                LDFLAGS="${LDFLAGS}  -L${with_libhiredis_libraries}"
            fi
            AC_CHECK_LIB(hiredis, redisConnect,, HIREDIS="no")
        fi
        if test "$HIREDIS" = "no"; then
            echo
            echo "   ERROR!  libhiredis library not found, go get it"
            echo "   from https://github.com/redis/hiredis or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libhiredis-dev"
            echo "   Fedora: dnf install hiredis-devel"
            echo "   RHEL/CentOS: yum install hiredis-devel"
            echo
            exit 1
        fi
        if test "$HIREDIS" = "yes"; then
            AC_DEFINE([HAVE_LIBHIREDIS],[1],[libhiredis available])
            enable_hiredis="yes"
            #
            # Check if async adapters and libevent is installed
            #
            AC_CHECK_HEADER("hiredis/adapters/libevent.h",HIREDIS_LIBEVENT_ADAPTER="yes",HIREDIS_LIBEVENT_ADAPTER="no")
            if test "$HIREDIS_LIBEVENT_ADAPTER" = "yes"; then
                #Look for libevent headers
                if test "$with_libevent_includes" != "no"; then
                    CPPFLAGS="${CPPFLAGS} -I${with_libevent_includes}"
                fi
                AC_CHECK_HEADER("event.h",LIBEVENT="yes",LIBEVENT="no")
                if test "$LIBEVENT" = "yes"; then
                    if test "$with_libevent_libraries" != "no"; then
                        LDFLAGS="${LDFLAGS}  -L${with_libevent_libraries}"
                    fi
                    AC_CHECK_LIB(event, event_base_free,, HAVE_LIBEVENT="no")
                    AC_CHECK_LIB(event_pthreads, evthread_use_pthreads,, HAVE_LIBEVENT_PTHREADS="no")
                fi
                if test "$HAVE_LIBEVENT" = "no" -o test "$HAVE_LIBEVENT_PTHREADS" = "no" ; then
                    if test "$HAVE_LIBEVENT" = "no"; then
                        echo
                        echo "  Async mode for redis output will not be available."
                        echo "  To enable it install libevent"
                        echo
                        echo "   Ubuntu: apt-get install libevent-dev"
                        echo "   Fedora: dnf install libevent-devel"
                        echo "   RHEL/CentOS: yum install libevent-devel"
                        echo
                   fi
                   if test "$HAVE_LIBEVENT_PTHREADS" = "no"; then
                        echo
                        echo "  Async mode for redis output will not be available."
                        echo "  To enable it install libevent with pthreads support"
                        echo
                        echo "   Ubuntu: apt-get install libevent-pthreads-2.0-5"
                        echo
                   fi
                else
                    AC_DEFINE([HAVE_LIBEVENT],[1],[libevent available])
                    enable_hiredis_async="yes"
                fi
            fi
        fi
    fi

# get cache line size
    AC_PATH_PROG(HAVE_GETCONF_CMD, getconf, "no")
    if test "$HAVE_GETCONF_CMD" != "no"; then
        CLS=$(getconf LEVEL1_DCACHE_LINESIZE)
        if [test "$CLS" != "" && test "$CLS" != "0"]; then
            AC_DEFINE_UNQUOTED([CLS],[${CLS}],[L1 cache line size])
        else
            AC_DEFINE([CLS],[64],[L1 cache line size])
        fi
    else
        AC_DEFINE([CLS],[64],[L1 cache line size])
    fi

# sphinx for documentation
    AC_PATH_PROG(HAVE_SPHINXBUILD, sphinx-build, "no")
    if test "$HAVE_SPHINXBUILD" = "no"; then
       enable_sphinxbuild=no
       if test -e "$srcdir/doc/userguide/suricata.1"; then
           have_suricata_man=yes
       fi
    fi
    AM_CONDITIONAL([HAVE_SPHINXBUILD], [test "x$enable_sphinxbuild" != "xno"])
    AM_CONDITIONAL([HAVE_SURICATA_MAN], [test "x$have_suricata_man" = "xyes"])

# pdflatex for the pdf version of the user manual
    AC_PATH_PROG(HAVE_PDFLATEX, pdflatex, "no")
    if test "$HAVE_PDFLATEX" = "no"; then
       enable_pdflatex=no
    fi
    AM_CONDITIONAL([HAVE_PDFLATEX], [test "x$enable_pdflatex" != "xno"])

# Cargo/Rust.
    AC_ARG_ENABLE([rust], AS_HELP_STRING([--enable-rust], [Enable Experimental Rust support]))
    AC_ARG_ENABLE([rust_experimental], AS_HELP_STRING([--enable-rust-experimental], [Enable support for experimental Rus parsers]))

    rust_config_enabled="no"        # used in suricata.yaml.in to enable/disable app-layers
    rust_config_comment="#"         # used in suricata.yaml.in to enable/disable eve loggers
    rust_config_exp_enabled="no"    # used in suricata.yaml.in to enable/disable app-layers
    rust_vendor_comment="# "
    have_rust_vendor="no"

    if test "x$enable_rust" != "xyes"; then
      enable_rust="no"
    else
      # Rust require jansson (json support).
      if test "x$enable_jansson" = "xno"; then
        echo ""
        echo "   ERROR! Rust support requires jansson."
        echo ""
        exit 1
      fi

      AC_PATH_PROG(HAVE_CARGO, cargo, "no")
      AC_PATH_PROG(HAVE_RUSTC, rustc, "no")

      # Deal with the case where Rust was requested but rustc or cargo
      # cannot be found.
      if test "x$HAVE_CARGO" = "xno"; then
        echo ""
        echo "   ERROR! Rust support requested but cargo not found."
        echo ""
        exit 1
      fi
      if test "x$HAVE_RUST" = "xno"; then
        echo ""
        echo "   ERROR! Rust support requested but rustc not found."
        echo ""
        exit 1
      fi

      if test "x$HAVE_CARGO" != "xno"; then
        if test "x$HAVE_RUSTC" != "xno"; then
          enable_rust="yes"
          AC_DEFINE([HAVE_RUST],[1],[Enable Rust language])
          if test "x$enable_debug" = "xyes"; then
            RUST_SURICATA_LIB="../rust/target/debug/libsuricata.a"
          else
            RUST_SURICATA_LIB="../rust/target/release/libsuricata.a"
          fi
          RUST_LDADD="${RUST_SURICATA_LIB} ${RUST_LDADD}"
          CFLAGS="${CFLAGS} -I\${srcdir}/../rust/gen/c-headers"
          AC_SUBST(RUST_SURICATA_LIB)
          AC_SUBST(RUST_LDADD)
          AC_SUBST([CARGO], [$HAVE_CARGO])
          if test "x$CARGO_HOME" = "x"; then
              AC_SUBST([CARGO_HOME], [~/.cargo])
          else
	          AC_SUBST([CARGO_HOME], [$CARGO_HOME])
          fi
          AC_CHECK_FILES([$srcdir/rust/vendor], [have_rust_vendor="yes"])
          if test "x$have_rust_vendor" = "xyes"; then
	          rust_vendor_comment=""
          fi

          rust_config_enabled="yes"
          rust_config_comment=""
        fi
      fi
    fi

    if test "x$enable_rust_experimental" = "xyes"; then
        rust_config_exp_enabled="yes"
        rust_config_exp_comment=""
    else
        enable_rust_experimental="no"
    fi

    AM_CONDITIONAL([HAVE_RUST], [test "x$enable_rust" = "xyes"])
    AM_CONDITIONAL([HAVE_RUST_EXTERNAL], [test "x$enable_rust_experimental" = "xyes"])
    AC_SUBST(rust_vendor_comment)
    AC_SUBST(rust_config_enabled)
    AC_SUBST(rust_config_comment)
    AC_SUBST(rust_config_exp_comment)
    AC_SUBST(rust_config_exp_enabled)
    AM_CONDITIONAL([HAVE_RUST_VENDOR], [test "x$have_rust_vendor" = "xyes"])

    if test "x$enable_rust" = "xyes"; then
      AC_PATH_PROG(HAVE_CARGO_VENDOR, cargo-vendor, "no")
      if test "x$HAVE_CARGO_VENDOR" = "xno"; then
        echo "   Warning: cargo-vendor not found, but it is only required"
        echo "       for building the distribution"
        echo "   To install: cargo install cargo-vendor"
      fi

      if test "x$enable_rust_experimental" = "xyes"; then
          AC_DEFINE([HAVE_RUST_EXTERNAL],[1],[Enable support for experimental Rust parsers])
      fi
    fi
    AM_CONDITIONAL([HAVE_CARGO_VENDOR], [test "x$HAVE_CARGO_VENDOR" != "xno"])

    AC_ARG_ENABLE(rust_strict,
           AS_HELP_STRING([--enable-rust-strict], [Rust warnings as errors]),,[enable_rust_strict=no])
    AS_IF([test "x$enable_rust_strict" = "xyes"], [
        RUST_FEATURES="strict"
    ])
    AC_SUBST(RUST_FEATURES)

# get revision
    if test -f ./revision; then
        REVISION=`cat ./revision`
        AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
    else
        AC_PATH_PROG(HAVE_GIT_CMD, git, "no")
        if test "$HAVE_GIT_CMD" != "no"; then
            if [ test -d .git ]; then
                REVISION=`git rev-parse --short HEAD`
                AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
            fi
        fi
    fi

AC_SUBST(CFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(CPPFLAGS)

define([EXPAND_VARIABLE],
[$2=[$]$1
if test $prefix = 'NONE'; then
	prefix="/usr/local"
fi
while true; do
  case "[$]$2" in
    *\[$]* ) eval "$2=[$]$2" ;;
    *) break ;;
  esac
done
eval "$2=[$]$2$3"
])dnl EXPAND_VARIABLE

# suricata log dir
if test "$WINDOWS_PATH" = "yes"; then
  systemtype="`systeminfo | grep \"based PC\"`"
  case "$systemtype" in
    *x64*)
      e_winbase="C:\\\\Program Files (x86)\\\\Suricata"
      ;;
    *)
      e_winbase="C:\\\\Program Files\\\\Suricata"
      ;;
  esac

  e_sysconfdir="$e_winbase\\\\"
  e_sysconfrulesdir="$e_winbase\\\\rules\\\\"
  e_magic_file="$e_winbase\\\\magic.mgc"
  e_logdir="$e_winbase\\\\log"
  e_logfilesdir="$e_logdir\\\\files"
  e_logcertsdir="$e_logdir\\\\certs"
else
  EXPAND_VARIABLE(localstatedir, e_logdir, "/log/suricata/")
  EXPAND_VARIABLE(localstatedir, e_rundir, "/run/")
  EXPAND_VARIABLE(localstatedir, e_logfilesdir, "/log/suricata/files")
  EXPAND_VARIABLE(localstatedir, e_logcertsdir, "/log/suricata/certs")
  EXPAND_VARIABLE(sysconfdir, e_sysconfdir, "/suricata/")
  EXPAND_VARIABLE(sysconfdir, e_sysconfrulesdir, "/suricata/rules")
  EXPAND_VARIABLE(localstatedir, e_localstatedir, "/run/suricata")
fi
AC_SUBST(e_logdir)
AC_SUBST(e_rundir)
AC_SUBST(e_logfilesdir)
AC_SUBST(e_logcertsdir)
AC_SUBST(e_sysconfdir)
AC_SUBST(e_sysconfrulesdir)
AC_SUBST(e_localstatedir)
AC_DEFINE_UNQUOTED([CONFIG_DIR],["$e_sysconfdir"],[Our CONFIG_DIR])
AC_SUBST(e_magic_file)
AC_SUBST(e_magic_file_comment)
AC_SUBST(e_enable_evelog)

EXPAND_VARIABLE(prefix, CONFIGURE_PREFIX)
EXPAND_VARIABLE(sysconfdir, CONFIGURE_SYSCONDIR)
EXPAND_VARIABLE(localstatedir, CONFIGURE_LOCALSTATEDIR)
AC_SUBST(CONFIGURE_PREFIX)
AC_SUBST(CONFIGURE_SYSCONDIR)
AC_SUBST(CONFIGURE_LOCALSTATEDIR)
AC_SUBST(PACKAGE_VERSION)

AC_OUTPUT(Makefile src/Makefile rust/Makefile rust/Cargo.toml rust/.cargo/config qa/Makefile qa/coccinelle/Makefile rules/Makefile doc/Makefile doc/userguide/Makefile contrib/Makefile contrib/file_processor/Makefile contrib/file_processor/Action/Makefile contrib/file_processor/Processor/Makefile contrib/tile_pcie_logd/Makefile suricata.yaml scripts/Makefile scripts/suricatasc/Makefile scripts/suricatasc/suricatasc etc/Makefile etc/suricata.logrotate etc/suricata.service)

SURICATA_BUILD_CONF="Suricata Configuration:
  AF_PACKET support:                       ${enable_af_packet}
  PF_RING support:                         ${enable_pfring}
  NFQueue support:                         ${enable_nfqueue}
  NFLOG support:                           ${enable_nflog}
  IPFW support:                            ${enable_ipfw}
  Netmap support:                          ${enable_netmap}
  DAG enabled:                             ${enable_dag}
  Napatech enabled:                        ${enable_napatech}

  Unix socket enabled:                     ${enable_unixsocket}
  Detection enabled:                       ${enable_detection}

  Libmagic support:                        ${enable_magic}
  libnss support:                          ${enable_nss}
  libnspr support:                         ${enable_nspr}
  libjansson support:                      ${enable_jansson}
  hiredis support:                         ${enable_hiredis}
  hiredis async with libevent:             ${enable_hiredis_async}
  Prelude support:                         ${enable_prelude}
  PCRE jit:                                ${pcre_jit_available}
  LUA support:                             ${enable_lua}
  libluajit:                               ${enable_luajit}
  libgeoip:                                ${enable_geoip}
  Non-bundled htp:                         ${enable_non_bundled_htp}
  Old barnyard2 support:                   ${enable_old_barnyard2}
  CUDA enabled:                            ${enable_cuda}
  Hyperscan support:                       ${enable_hyperscan}
  Libnet support:                          ${enable_libnet}

  Rust support (experimental):             ${enable_rust}
  Experimental Rust parsers:               ${enable_rust_experimental}
  Rust strict mode:                        ${enable_rust_strict}

  Suricatasc install:                      ${enable_python}

  Profiling enabled:                       ${enable_profiling}
  Profiling locks enabled:                 ${enable_profiling_locks}

Development settings:
  Coccinelle / spatch:                     ${enable_coccinelle}
  Unit tests enabled:                      ${enable_unittests}
  Debug output enabled:                    ${enable_debug}
  Debug validation enabled:                ${enable_debug_validation}

Generic build parameters:
  Installation prefix:                     ${prefix}
  Configuration directory:                 ${e_sysconfdir}
  Log directory:                           ${e_logdir}

  --prefix                                 ${CONFIGURE_PREFIX}
  --sysconfdir                             ${CONFIGURE_SYSCONDIR}
  --localstatedir                          ${CONFIGURE_LOCALSTATEDIR}

  Host:                                    ${host}
  Compiler:                                ${CC} (exec name) / ${compiler} (real)
  GCC Protect enabled:                     ${enable_gccprotect}
  GCC march native enabled:                ${enable_gccmarch_native}
  GCC Profile enabled:                     ${enable_gccprofile}
  Position Independent Executable enabled: ${enable_pie}
  CFLAGS                                   ${CFLAGS}
  PCAP_CFLAGS                              ${PCAP_CFLAGS}
  SECCFLAGS                                ${SECCFLAGS}"

echo
echo "$SURICATA_BUILD_CONF"
echo "printf(" >src/build-info.h
echo "$SURICATA_BUILD_CONF" | sed -e 's/^/"/' | sed -e 's/$/\\n"/' >>src/build-info.h
echo ");" >>src/build-info.h

echo "
To build and install run 'make' and 'make install'.

You can run 'make install-conf' if you want to install initial configuration
files to ${e_sysconfdir}. Running 'make install-full' will install configuration
and rules and provide you a ready-to-run suricata."
echo
echo "To install Suricata into /usr/bin/suricata, have the config in
/etc/suricata and use /var/log/suricata as log dir, use:
./configure --prefix=/usr/ --sysconfdir=/etc/ --localstatedir=/var/"
echo
