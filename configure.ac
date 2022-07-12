    AC_INIT([suricata],[6.0.6])
    m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])
    AC_CONFIG_HEADERS([src/autoconf.h])
    AC_CONFIG_SRCDIR([src/suricata.c])
    AC_CONFIG_MACRO_DIR(m4)
    AM_INIT_AUTOMAKE([tar-ustar subdir-objects])

    AC_LANG([C])
    LT_INIT
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

    AC_ARG_WITH([clang],
                [  --with-clang=PROGRAM    path to Clang for compiling eBPF code. Use if the main C compiler is not Clang.],
                [CLANG="$withval"],
                [AS_IF([test "$compiler" = clang],
                       [CLANG="$CC"],
                       [AC_PATH_PROG([CLANG],[clang])])])

    AC_SUBST([CLANG])

    case "$compiler" in
        clang)
            CLANG_CFLAGS="-Wextra -Werror-implicit-function-declaration -Wno-error=unused-command-line-argument"
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
    AC_PROG_RANLIB
    AC_PROG_INSTALL
    AC_PROG_LN_S
    AC_PROG_MAKE_SET
    AC_PROG_GREP

    AC_PATH_PROG(HAVE_CYGPATH, cygpath, "no")
    AM_CONDITIONAL([HAVE_CYGPATH], [test "x$HAVE_CYGPATH" != "xno"])

    AC_PATH_PROG(HAVE_PKG_CONFIG, pkg-config, "no")
    if test "$HAVE_PKG_CONFIG" = "no"; then
        echo
        echo "   ERROR! pkg-config not found, go get it  "
        echo "   http://pkg-config.freedesktop.org/wiki/ "
        echo "   or install from your distribution       "
        echo
        exit 1
    fi

    python_path="not set"

    AC_ARG_ENABLE(python,
           AS_HELP_STRING([--enable-python], [Enable python]),
	   [enable_python=$enableval],[enable_python=yes])
    if test "x$enable_python" != "xyes"; then
        enable_python="no"
    else
        AC_PATH_PROGS(HAVE_PYTHON, python3 python2.7 python2 python, "no")
        if test "$HAVE_PYTHON" = "no"; then
            echo
            echo "   Warning! Python not found."
            echo
            echo "   Python is required for additional tools like"
            echo "   suricatasc, suricatactl and suricata-update."
            echo "   It is also required when building from git."
            echo
            enable_python="no"
	else
	    python_path="$HAVE_PYTHON"
        fi
    fi
    AM_CONDITIONAL([HAVE_PYTHON], [test "x$enable_python" = "xyes"])

    # Get the Python major version. This is only for information
    # messages displayed during configure.
    if test "x$HAVE_PYTHON" != "xno"; then
       pymv="$($HAVE_PYTHON -c 'import sys; print(sys.version_info[[0]]);')"
    fi

    # Check for python-distutils (setup).
    have_python_distutils="no"
    if test "x$enable_python" = "xyes"; then
        AC_MSG_CHECKING([for python-distutils])
	if $HAVE_PYTHON -c "import distutils; from distutils.core import setup" 2>/dev/null; then
	   AC_MSG_RESULT([yes])
	   have_python_distutils="yes"
	else
	   AC_MSG_RESULT([no])
	fi
    fi
    AM_CONDITIONAL([HAVE_PYTHON_DISTUTILS],
	[test "x$have_python_distutils" = "xyes"])
    if test "$have_python_distutils" = "no"; then
       echo ""
       echo "    Warning: Python distutils not found. Python tools will"
       echo "        not be installed."
       echo ""
       echo "    Install the distutils module for Python ${pymv} to enable"
       echo "    the Python tools."
       echo ""
    fi

    # Check for python-yaml.
    have_python_yaml="no"
    if test "x$enable_python" = "xyes"; then
        AC_MSG_CHECKING([for python-yaml])
	if $HAVE_PYTHON -c "import yaml" 2>/dev/null; then
	   have_python_yaml="yes"
	   AC_MSG_RESULT([yes])
	else
	   AC_MSG_RESULT([no])
	fi
    fi
    AM_CONDITIONAL([HAVE_PYTHON_YAML], [test "x$have_python_yaml" = "xyes"])

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
    AC_CHECK_HEADERS([sys/time.h time.h unistd.h sys/param.h])
    AC_CHECK_HEADERS([sys/ioctl.h linux/if_ether.h linux/if_packet.h linux/filter.h])
    AC_CHECK_HEADERS([linux/ethtool.h linux/sockios.h])
    AC_CHECK_HEADERS([glob.h locale.h grp.h pwd.h])
    AC_CHECK_HEADERS([dirent.h fnmatch.h])
    AC_CHECK_HEADERS([sys/resource.h sys/types.h sys/un.h])
    AC_CHECK_HEADERS([sys/random.h])
    AC_CHECK_HEADERS([utime.h])
    AC_CHECK_HEADERS([libgen.h])
    AC_CHECK_HEADERS([mach/mach.h])
    AC_CHECK_HEADERS([stdatomic.h])

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
    AC_C_RESTRICT
    AC_TYPE_PID_T
    AC_TYPE_MODE_T
    AC_TYPE_SIZE_T
    AC_TYPE_SSIZE_T
    AC_TYPE_INT8_T
    AC_TYPE_INT16_T
    AC_TYPE_INT32_T
    AC_TYPE_INT64_T
    AC_TYPE_UINT8_T
    AC_TYPE_UINT16_T
    AC_TYPE_UINT32_T
    AC_TYPE_UINT64_T
    AC_TYPE_UINT
    AC_TYPE_USHORT
    AC_TYPE_ULONG
    AC_TYPE_UCHAR
    AC_STRUCT_TIMEZONE
    AC_CHECK_TYPES([ptrdiff_t])
    AC_HEADER_STDBOOL

    # Checks for library functions.
    AC_FUNC_MALLOC
    AC_FUNC_REALLOC
    AC_FUNC_FORK
    AC_FUNC_MKTIME
    AC_FUNC_MMAP
    AC_FUNC_STRTOD

    AC_CHECK_FUNCS([memmem memset memchr memrchr memmove])
    AC_CHECK_FUNCS([strcasecmp strchr strrchr strdup strndup strncasecmp strtol strtoul strstr strpbrk strtoull strtoumax])
    AC_CHECK_FUNCS([strerror])
    AC_CHECK_FUNCS([gethostname inet_ntoa uname])
    AC_CHECK_FUNCS([gettimeofday clock_gettime utime strptime tzset localtime_r])
    AC_CHECK_FUNCS([socket setenv select putenv dup2 endgrent endpwent atexit munmap])

    AC_CHECK_FUNCS([fwrite_unlocked])

    AC_CHECK_DECL([getrandom],
        AC_DEFINE([HAVE_GETRANDOM], [1], [Use getrandom]),
        [], [
            #include <sys/random.h> 
            ])

    OCFLAGS=$CFLAGS
    CFLAGS=""
    AC_CHECK_FUNCS([strlcpy strlcat])
    CFLAGS=$OCFLAGS

    # Add large file support
    AC_SYS_LARGEFILE

    #check for os
    AC_MSG_CHECKING([host os])

    # Default lua libname if not detected otherwise.
    LUA_LIB_NAME="lua5.1"

    # If no host os was detected, try with uname
    if test -z "$host" ; then
	    host="`uname`"
    fi
    echo -n "installation for $host OS... "

    RUST_SURICATA_LIBNAME="libsuricata.a"

    e_magic_file=""
    e_magic_file_comment="#"
    PCAP_LIB_NAME="pcap"
    case "$host" in
        *-*-*freebsd*)
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_FREEBSD"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet11"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -L/usr/local/lib/libnet11"
            RUST_LDADD="-lrt -lm"
            ;;
        *-*-openbsd*)
            CFLAGS="${CFLAGS} -D__OpenBSD__"
            CPPFLAGS="${CPPFLAGS} -I/usr/local/include -I/usr/local/include/libnet-1.1"
            LDFLAGS="${LDFLAGS} -L/usr/local/lib -I/usr/local/lib/libnet-1.1"
            RUST_LDADD="-lm -lc++ -lc++abi"
            ;;
        *darwin*|*Darwin*)
            LUA_LIB_NAME="lua-5.1"
            CFLAGS="${CFLAGS} -DOS_DARWIN"
            CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
            LDFLAGS="${LDFLAGS} -L/opt/local/lib"
            ;;
        *-*-linux*)
            RUST_LDADD="-ldl -lrt -lm"
            ;;
        *-*-mingw32*|*-*-msys)
            CFLAGS="${CFLAGS} -DOS_WIN32"
            WINDOWS_PATH="yes"
            PCAP_LIB_NAME="wpcap"
            AC_DEFINE([HAVE_NON_POSIX_MKDIR], [1], [mkdir is not POSIX compliant: single arg])
            RUST_LDADD=" -lws2_32 -liphlpapi -lwbemuuid -lOle32 -lOleAut32 -lUuid -luserenv -lshell32 -ladvapi32 -lgcc_eh -lbcrypt"
            ;;
        *-*-cygwin)
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

    # check if our target supports c11
    AC_MSG_CHECKING(for c11 support)
    OCFLAGS=$CFLAGS
    CFLAGS="-std=c11"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>]],
                [[ static _Thread_local int i; i = 1; i++; ]])],
            AC_MSG_RESULT([yes])
            [AC_DEFINE([TLS_C11], [1], [C11 Thread local storage])
             CFLAGS="$OCFLAGS -std=c11"],
            [AC_MSG_RESULT([no])
             CFLAGS="$OCFLAGS"
             have_c11=no
             have_c11_tls=no])
    if [ test "x$have_c11" = "xno" ]; then
        CFLAGS="$CFLAGS -std=gnu99"
    fi

    # check if our target supports thread local storage
    AC_MSG_CHECKING(for thread local storage gnu __thread support)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdlib.h>]],
                [[ static __thread int i; i = 1; i++; ]])],
            [AC_DEFINE([TLS_GNU], [1], [Thread local storage])
            AC_MSG_RESULT([yes])],
            [AC_MSG_RESULT([no])
             have_gnu_tls=no])
    if [ test "x$have_c11_tls" = "xno" ] && [ test "x$have_gnu_tls" = "xno" ]; then
        AC_MSG_ERROR("no thread local support available.")
        exit 1
    fi

    #Enable support for gcc compile time security options. There is no great way to do detection of valid cflags that I have found
    #AX_CFLAGS_GCC_OPTION don't seem to do a better job than the code below and are a pain because of extra m4 files etc.
    #These flags seem to be supported on CentOS 5+, Ubuntu 8.04+, and FedoreCore 11+
    #Options are taken from https://wiki.ubuntu.com/CompilerFlags
    AC_ARG_ENABLE(gccprotect,
           AS_HELP_STRING([--enable-gccprotect], [Detect and use gcc hardening options]),[enable_gccprotect=$enableval],[enable_gccprotect=no])

    AS_IF([test "x$enable_gccprotect" = "xyes"], [
        #buffer overflow protection
        AC_MSG_CHECKING(for -fstack-protector)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -fstack-protector"
        AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[SECCFLAGS="-fstack-protector"
            AC_MSG_RESULT(yes)],
            [AC_MSG_RESULT(no)])
        CFLAGS="${TMPCFLAGS}"

        #compile-time best-practices errors for certain libc functions, provides checks of buffer lengths and memory regions
        AC_MSG_CHECKING(for -D_FORTIFY_SOURCE=2)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -D_FORTIFY_SOURCE=2"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[SECCFLAGS="${SECCFLAGS} -D_FORTIFY_SOURCE=2"
            AC_MSG_RESULT(yes)],
            [AC_MSG_RESULT(no)])
        CFLAGS="${TMPCFLAGS}"

        #compile-time warnings about misuse of format strings
        AC_MSG_CHECKING(for -Wformat -Wformat-security)
        TMPCFLAGS="${CFLAGS}"
        CFLAGS="${CFLAGS} -Wformat -Wformat-security"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[SECCFLAGS="${SECCFLAGS} -Wformat -Wformat-security"
            AC_MSG_RESULT(yes)],
            [AC_MSG_RESULT(no)])
        CFLAGS="${TMPCFLAGS}"

        #provides a read-only relocation table area in the final ELF
        AC_MSG_CHECKING(for -z relro)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z relro"
        AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[SECLDFLAGS="${SECLDFLAGS} -z relro"
            AC_MSG_RESULT(yes)],
            [AC_MSG_RESULT(no)])
        LDFLAGS="${TMPLDFLAGS}"

        #forces all relocations to be resolved at run-time
        AC_MSG_CHECKING(for -z now)
        TMPLDFLAGS="${LDFLAGS}"
        LDFLAGS="${LDFLAGS} -z now"
        AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],[SECLDFLAGS="${SECLDFLAGS} -z now"
            AC_MSG_RESULT(yes)],
            [AC_MSG_RESULT(no)])
        LDFLAGS="${TMPLDFLAGS}"

        AC_SUBST(SECCFLAGS)
        AC_SUBST(SECLDFLAGS)
    ])

    #check for plugin support
    AC_CHECK_HEADERS([dlfcn.h])
    AC_MSG_CHECKING([for plugin support])
    TMPLDFLAGS="${LDFLAGS}"
    LDFLAGS="${LDFLAGS} -rdynamic"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <dlfcn.h>]], [[]])],
        [
            AC_MSG_RESULT(yes)
            has_rdynamic=yes
        ],
        [
            AC_MSG_RESULT(no)
            has_rdynamic=no
        ])

    if test "x$has_rdynamic" = "xyes"; then
        plugin_support=yes
        AC_DEFINE([HAVE_PLUGINS], [1], [Plugin support])
    else
        plugin_support=no
        LDFLAGS="${TMPLDFLAGS}"
    fi

    #enable profile generation
    AC_ARG_ENABLE(gccprofile,
           AS_HELP_STRING([--enable-gccprofile], [Enable gcc profile info i.e -pg flag is set]),[enable_gccprofile=$enableval],[enable_gccprofile=no])
    AS_IF([test "x$enable_gccprofile" = "xyes"], [
        CFLAGS="${CFLAGS} -pg"
    ])

    #enable gcc march=native gcc 4.2 or later
    AC_ARG_ENABLE(gccmarch_native,
           AS_HELP_STRING([--enable-gccmarch-native], [Enable gcc march=native gcc 4.2 and later only]),[enable_gccmarch_native=$enableval],[enable_gccmarch_native=yes])
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
           AS_HELP_STRING([--enable-unittests], [Enable compilation of the unit tests]),[enable_unittests=$enableval],[enable_unittests=no])
    AS_IF([test "x$enable_unittests" = "xyes"], [
        AC_DEFINE([UNITTESTS],[1],[Enable built-in unittests])
    ])
    AM_CONDITIONAL([BUILD_UNITTESTS], [test "x$enable_unittests" = "xyes"])

  # enable the building of ebpf files 
    AC_ARG_ENABLE(ebpf-build,
           AS_HELP_STRING([--enable-ebpf-build], [Enable compilation of ebpf files]),[enable_ebpf_build=$enableval],[enable_ebpf_build=no])
    AM_CONDITIONAL([BUILD_EBPF], [test "x$enable_ebpf_build" = "xyes"])

    AS_IF([test "x$enable_ebpf_build" = "xyes"],
          [
            AS_IF([test "$CLANG" != no],
                  [
                    llc_candidates=$($CLANG --version | \
                      awk '/^clang version/ {
                             split($3, v, ".");
                             printf("llc-%s.%s llc-%s llc", v[[1]], v[[2]], v[[1]])
                           }')
                    AC_CHECK_PROGS([LLC], [$llc_candidates], "no")
                    if test "$LLC" = "no"; then
                        AC_MSG_ERROR([unable to find any of $llc_candidates needed to build ebpf files])
                    fi
                    AC_SUBST(LLC)
                  ],
                  [AC_MSG_ERROR([clang needed to build ebpf files])])
          ])

  # enable debug output
    AC_ARG_ENABLE(debug,
           AS_HELP_STRING([--enable-debug], [Enable debug output]),[enable_debug=$enableval],[enable_debug=no])
    AS_IF([test "x$enable_debug" = "xyes"], [
        AC_DEFINE([DEBUG],[1],[Enable debug output])
    ])
    AM_CONDITIONAL([DEBUG], [test "x$enable_debug" = "xyes"])

  # enable debug validation functions & macro's output
    AC_ARG_ENABLE(debug-validation,
           AS_HELP_STRING([--enable-debug-validation], [Enable (debug) validation code output]),[enable_debug_validation=$enableval],[enable_debug_validation=no])
    AS_IF([test "x$enable_debug_validation" = "xyes"], [
        if test "$enable_unittests" = "yes"; then
            AC_MSG_ERROR([debug_validation can't be enabled with enabled unittests!])
        else
            AC_DEFINE([DEBUG_VALIDATION],[1],[Enable (debug) validation code output])
        fi
    ])
    AM_CONDITIONAL([DEBUG_VALIDATION], [test "x$enable_debug_validation" = "xyes"])

  # enable http2 decompression
     AC_ARG_ENABLE(http2-decompression,
            AS_HELP_STRING([--enable-http2-decompression], [Enable http2 decompression]),[enable_http2_decompression=$enableval],[enable_http2_decompression=no])
     AS_IF([test "x$enable_http2_decompression" = "xyes"], [
         AC_DEFINE([HTTP2_DECOMPRESSION],[1],[Enable http2 decompression])
     ])
     AM_CONDITIONAL([HTTP2_DECOMPRESSION], [test "x$enable_http2_decompression" = "xyes"])

  # profiling support
    AC_ARG_ENABLE(profiling,
           AS_HELP_STRING([--enable-profiling], [Enable performance profiling]),[enable_profiling=$enableval],[enable_profiling=no])
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
           AS_HELP_STRING([--enable-profiling-locks], [Enable performance profiling for locks]),[enable_profiling_locks=$enableval],[enable_profiling_locks=no])
    AS_IF([test "x$enable_profiling_locks" = "xyes"], [
        AC_DEFINE([PROFILING],[1],[Enable performance profiling])
        AC_DEFINE([PROFILE_LOCKING],[1],[Enable performance profiling for locks])
    ])

  # enable support for IPFW
    AC_ARG_ENABLE(ipfw,
            AS_HELP_STRING([--enable-ipfw], [Enable FreeBSD IPFW support for inline IDP]),[enable_ipfw=$enableval],[enable_ipfw=no])
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

# libraries

  # zlib
    AC_ARG_WITH(zlib_includes,
            [  --with-zlib-includes=DIR  zlib include directory],
            [with_zlib_includes="$withval"],[with_zlib_includes=no])
    AC_ARG_WITH(zlib_libraries,
            [  --with-zlib-libraries=DIR    zlib library directory],
            [with_zlib_libraries="$withval"],[with_zlib_libraries="no"])

    if test "$with_zlib_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_zlib_includes}"
    fi

    AC_CHECK_HEADER(zlib.h, ZLIB="yes",ZLIB="no")
    if test "$ZLIB" = "yes"; then
        if test "$with_zlib_libraries" != "no"; then
            LDFLAGS="${LDFLAGS}  -L${with_zlib_libraries}"
        fi

        # To prevent duping the lib link we reset LIBS after this check. Setting action-if-found to NULL doesn't seem to work
        # see: http://blog.flameeyes.eu/2008/04/29/i-consider-ac_check_lib-harmful
        ZLIB=""
        TMPLIBS="${LIBS}"
        AC_CHECK_LIB(z,inflate,,ZLIB="no")

        if test "$ZLIB" = "no"; then
            echo
            echo "   ERROR!  zlib library not found, go get it"
            echo "   Debian/Ubuntu: apt install zlib1g-dev"
            echo "   Fedora: dnf install zlib-devel"
            echo "   CentOS/RHEL: yum install zlib-devel"
            echo
            exit 1
        fi
        LIBS="${TMPLIBS} -lz"
    fi

  #libpcre
    AC_ARG_WITH(libpcre_includes,
            [  --with-libpcre-includes=DIR  libpcre include directory],
            [with_libpcre_includes="$withval"],[with_libpcre_includes="no"])
    AC_ARG_WITH(libpcre_libraries,
            [  --with-libpcre-libraries=DIR    libpcre library directory],
            [with_libpcre_libraries="$withval"],[with_libpcre_libraries="no"])

    if test "$with_libpcre_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libpcre_includes}"
    fi
    AC_CHECK_HEADER(pcre.h,,[AC_MSG_ERROR(pcre.h not found ...)])

    if test "$with_libpcre_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_libpcre_libraries}"
    fi
    PCRE=""
    AC_CHECK_LIB(pcre, pcre_get_substring,,PCRE="no")
    if test "$PCRE" = "no"; then
        echo
        echo "   ERROR!  pcre library not found, go get it"
        echo "   from www.pcre.org. Or from packages:"
        echo "   Debian/Ubuntu: apt install libpcre3-dev"
        echo "   Fedora: dnf install pcre-devel"
        echo "   CentOS/RHEL: yum install pcre-devel"
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

    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <pcre.h> ]],
        [[ int eo = 0; eo |= PCRE_EXTRA_MATCH_LIMIT_RECURSION; ]])],
        [ pcre_match_limit_recursion_available=yes ],[:]
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
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <pcre.h> ]],
        [[ pcre_extra *extra = NULL; pcre_free_study(extra); ]])],
        [ AC_DEFINE([HAVE_PCRE_FREE_STUDY], [1], [Pcre pcre_free_study supported])],[:]
    )
    CFLAGS="${TMPCFLAGS}"

    #enable support for PCRE-jit available since pcre-8.20
    AC_MSG_CHECKING(for PCRE JIT support)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <pcre.h> ]],
        [[
        int jit = 0;
        pcre_config(PCRE_CONFIG_JIT, &jit);
        ]])],[ pcre_jit_available=yes ],[ pcre_jit_available=no ]
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
            # hack: use libatomic
            LIBS="${LIBS} -latomic"
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
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <pcre.h> ]],
           [[
           const char *error;
           int err_offset;
           pcre *re = pcre_compile("(a|b|c|d)",0, &error, &err_offset,NULL);
           pcre_extra *extra = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
           if (extra == NULL)
               exit(EXIT_FAILURE);
           int jit = 0;
           int ret = pcre_fullinfo(re, extra, PCRE_INFO_JIT, &jit);
           if (ret != 0 || jit != 1)
               exit(EXIT_FAILURE);
           exit(EXIT_SUCCESS);
           ]])],[ pcre_jit_works=yes ],[:]
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

    if test "x$pcre_jit_works" = "xyes"; then

       AC_MSG_CHECKING(for PCRE JIT exec availability)
       AC_LINK_IFELSE(
           [AC_LANG_PROGRAM(
               [
                  #include <pcre.h>
                  #include <string.h>
               ],
               [
                   const char *error;
                   int err_offset;
                   pcre *re = pcre_compile("(a|b|c|d)", 0, &error, &err_offset,NULL);
                   pcre_extra *study = pcre_study(re, PCRE_STUDY_JIT_COMPILE, &error);
                   if (study == NULL)
                       exit(EXIT_FAILURE);
                   pcre_jit_stack *stack = pcre_jit_stack_alloc(32*1024,40*1024);
                   if (stack == 0)
                       exit(EXIT_FAILURE);
                   int ret = pcre_jit_exec(re, study, "apple", 5, 0, 0, NULL, 0, stack);
                   exit(ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
               ])],
           [pcre_jit_exec_available="yes" ],
           [pcre_jit_exec_available="no" ])
       if test "x$pcre_jit_exec_available" != "xyes"; then
           AC_MSG_RESULT(no)
       else
           AC_MSG_RESULT(yes)
           AC_DEFINE([PCRE_HAVE_JIT_EXEC], [1], [PCRE with JIT compiler support enabled supporting pcre_jit_exec])
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
        echo "   Fedora: dnf install libyaml-devel"
        echo "   CentOS/RHEL: yum install libyaml-devel"
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

    dnl AC_CHECK_HEADER(pthread.h,,[AC_MSG_ERROR(pthread.h not found ...)])

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

    AC_CHECK_FUNCS([pthread_spin_unlock])

    AS_IF([test "x$enable_debug" = "xyes"], [
        # Debug only function used for diagnostic display
        AC_CHECK_FUNCS([pthread_getattr_np])
    ])

  # libjansson
    AC_ARG_WITH(libjansson_includes,
            [  --with-libjansson-includes=DIR  libjansson include directory],
            [with_libjansson_includes="$withval"],[with_libjansson_includes=no])
    AC_ARG_WITH(libjansson_libraries,
            [  --with-libjansson-libraries=DIR    libjansson library directory],
            [with_libjansson_libraries="$withval"],[with_libjansson_libraries="no"])

    if test "$with_libjansson_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_libjansson_includes}"
    fi

    if test "$with_libjansson_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libjansson_libraries}"
    fi

    AC_CHECK_HEADER(jansson.h,JANSSON="yes",JANSSON="no")
    AC_CHECK_LIB(jansson, json_dump_callback,, JANSSON="no")

    if test "$JANSSON" = "no"; then
       echo ""
       echo "    ERROR: Jansson is now required."
       echo ""
       echo "    Go get it from your distribution or from:"
       echo "      http://www.digip.org/jansson/"
       echo ""
       echo "    Ubuntu/Debian: apt install libjansson-dev"
       echo "    CentOS: yum install jansson-devel"
       echo "    Fedora: dnf install jansson-devel"
       echo ""
       exit 1
    fi

    enable_jansson="yes"
    enable_unixsocket="no"

    AC_ARG_ENABLE(unix-socket,
           AS_HELP_STRING([--enable-unix-socket], [Enable unix socket [default=test]]),[enable_unixsocket="$enableval"],[enable_unixsocket=test])

    if test "$JANSSON" = "yes"; then
        enable_jansson="yes"
        if test "$JANSSON" = "no"; then
            echo
            echo "   Jansson >= 2.2 is required for features like unix socket"
            echo "   Go get it from your distribution or from:"
            echo "   http://www.digip.org/jansson/"
            echo "   Ubuntu: apt-get install libjansson-dev"
            echo "   Fedora: dnf install jansson-devel"
            echo "   CentOS/RHEL: yum install jansson-devel"
            echo
            if test "x$enable_unixsocket" = "xyes"; then
                exit 1
            fi
            enable_unixsocket="no"
            enable_jansson="no"
        else
            case $host in
                *-*-mingw32*|*-*-msys*|*-*-cygwin)
                    enable_unixsocket="no"
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
            echo "   Ubuntu: apt-get install libjansson-dev"
            echo "   Fedora: dnf install jansson-devel"
            echo "   CentOS/RHEL: yum install jansson-devel"
            echo
            exit 1
        fi
        enable_unixsocket="no"
    fi

    AS_IF([test "x$enable_unixsocket" = "xyes"], [AC_DEFINE([BUILD_UNIX_SOCKET], [1], [Unix socket support enabled])])
    e_enable_evelog=$enable_jansson

    AC_ARG_ENABLE(nflog,
            AS_HELP_STRING([--enable-nflog],[Enable libnetfilter_log support]),
                           [ enable_nflog="$enableval"],
                           [ enable_nflog="no"])
    AC_ARG_ENABLE(nfqueue,
           AS_HELP_STRING([--enable-nfqueue], [Enable NFQUEUE support for inline IDP]),[enable_nfqueue=$enableval],[enable_nfqueue=no])
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
                echo "   nfnetlink library not found, go get it"
                echo "   from www.netfilter.org."
                echo "   we automatically append libnetfilter_queue/ when searching"
                echo "   for headers etc. when the --with-libnfnetlink-includes directive"
                echo "   is used"
                echo "   Ubuntu: apt-get install libnetfilter-queue-dev"
                echo "   Fedora: dnf install libnetfilter_queue-devel"
                echo "   CentOS/RHEL: yum install libnetfilter_queue-devel"
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

        AC_CHECK_HEADER(libnetfilter_queue/libnetfilter_queue.h,,
            [AC_MSG_ERROR(libnetfilter_queue/libnetfilter_queue.h not found ...)],
            [
                #define _GNU_SOURCE
                #include <sys/types.h>
                #include <stdint.h>
            ])

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
                    #define _GNU_SOURCE
                    #include <sys/types.h>
                    #include <stdint.h>
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
            echo "   Ubuntu: apt-get install libnetfilter-queue-dev"
            echo "   Fedora: dnf install libnetfilter_queue-devel"
            echo "   CentOS/RHEL: yum install libnetfilter_queue-devel"
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

        AC_CHECK_HEADER(libnetfilter_log/libnetfilter_log.h,,[AC_MSG_ERROR(libnetfilter_log.h not found ...)])

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

  # WinDivert support
    AC_ARG_ENABLE(windivert,
        AS_HELP_STRING([--enable-windivert],[Enable WinDivert support [default=no]]),[enable_windivert=$enableval],
        [enable_windivert="no"])
    
  # WinDivert can only be enabled on Windows builds
    AC_CHECK_DECL([OS_WIN32],,[enable_windivert="no"])

    if test "x$enable_windivert" = "xyes"; then
        # WinDivert requires Vista at a minimum. If the user has selected their own NTDDI_VERSION
        # then don't override it.
        AC_CHECK_DECL([NTDDI_VERSION],,
                [CFLAGS="${CFLAGS} -DNTDDI_VERSION=NTDDI_VISTA -D_WIN32_WINNT=_WIN32_WINNT_VISTA"])

        AC_DEFINE_UNQUOTED([WINDIVERT],[1],[Enable Windows WinDivert support for inline IDP])

        AC_ARG_WITH(windivert_include,
                [  --with-windivert-include=DIR WinDivert include path],
                [with_windivert_include="$withval"],[with_windivert_include="no"])
        AC_ARG_WITH(windivert_libraries,
                [  --with-windivert-libraries=DIR WinDivert library path],
                [with_windivert_libraries="$withval"],[with_windivert_libraries="no"])

        if test "$with_windivert_include" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_windivert_include}"
        fi

        if test "$with_windivert_libraries" != "no"; then
            LDFLAGS="${LDFLAGS} -L${with_windivert_libraries}"
        fi

        AC_CHECK_HEADER(windivert.h,,WINDIVERT_INC="no")
        AC_CHECK_LIB(WinDivert, WinDivertOpen,, WINDIVERT_LIB="no")

        if test "$WINDIVERT_LIB" = "no" || test "$WINDIVERT_INC" = "no"; then
            echo
            echo "    ERROR! WinDivert not found, go get it from"
            echo "    https://www.reqrypt.org/windivert.html"
            echo
            exit 1
        fi
    fi
  # /WinDivert

  # prelude
    AC_ARG_ENABLE(prelude,
            AS_HELP_STRING([--enable-prelude], [Enable Prelude support for alerts]),[enable_prelude=$enableval],[enable_prelude=no])
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
            # https://www.inliniac.net/blog/2007/10/16/libnet-11-ipv6-fixes-and-additions.html
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

    AC_CHECK_HEADERS([pcap.h],[],[AC_MSG_ERROR(pcap.h not found ...)],
            [[
                #ifdef HAVE_WINSOCK2_H
                #include <winsock2.h>
                #endif
                #define _DEFAULT_SOURCE 1
            ]])

    if test "$with_libpcap_libraries" != "no"; then
        LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
    fi
    AC_CHECK_HEADERS([pcap.h pcap/pcap.h pcap/bpf.h],[],[],
            [[
                #ifdef HAVE_WINSOCK2_H
                #include <winsock2.h>
                #endif
                #define _DEFAULT_SOURCE 1
            ]])

    LIBPCAP=""
    PKG_CHECK_MODULES([PCAP],libpcap,[CPPFLAGS="${CPPFLAGS} ${PCAP_CFLAGS}" LIBS="${LIBS} ${PCAP_LIBS}"],[:])
    AC_CHECK_LIB(${PCAP_LIB_NAME}, pcap_open_live,, LIBPCAP="no")
    if test "$LIBPCAP" = "no"; then
        echo
        echo "   ERROR!  libpcap library not found, go get it"
        echo "   from http://www.tcpdump.org or your distribution:"
        echo
        echo "   Ubuntu: apt-get install libpcap-dev"
        echo "   Fedora: dnf install libpcap-devel"
        echo "   CentOS/RHEL: yum install libpcap-devel"
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
        echo "   Fedora: dnf install libpcap-devel"
        echo "   CentOS/RHEL: yum install libpcap-devel"
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
           AS_HELP_STRING([--enable-pfring], [Enable Native PF_RING support]),[enable_pfring=$enableval],[enable_pfring=no])
    AS_IF([test "x$enable_pfring" = "xyes"], [
        AC_DEFINE([HAVE_PFRING],[1],(PF_RING support enabled))

        #We have to set CFLAGS for AC_COMPILE_IFELSE as it doesn't pay attention to CPPFLAGS
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
            AC_COMPILE_IFELSE(
                [AC_LANG_SOURCE([[
                    #include <pfring.h>
                    #ifndef PF_RING_FLOW_OFFLOAD
                    # error PF_RING_FLOW_OFFLOAD not defined
                    #endif
                ]])],
                [
                    AC_DEFINE([HAVE_PF_RING_FLOW_OFFLOAD], [1], [PF_RING bypass support enabled])
                ],
                [
                    echo
                    echo "   Warning! Pfring hw bypass not supported by this library version < 7,"
                    echo "   please upgrade to a newer version to use this feature."
                    echo
                    echo "   Continuing for now with hw bypass support disabled..."
                    echo
                ])
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
                        [enable_af_packet=$enableval],[enable_af_packet=yes])
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
            AS_HELP_STRING([--enable-netmap], [Enable Netmap support]),[enable_netmap=$enableval],[enable_netmap=no])
    AC_ARG_WITH(netmap_includes,
            [  --with-netmap-includes=DIR netmap include directory],
            [with_netmap_includes="$withval"],[with_netmap_includes=no])

    AS_IF([test "x$enable_netmap" = "xyes"], [
        AC_DEFINE([HAVE_NETMAP],[1],(NETMAP support enabled))

        if test "$with_netmap_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_netmap_includes}"
        fi

        AC_CHECK_HEADER(net/netmap_user.h,,[AC_MSG_ERROR(net/netmap_user.h not found ...)],)

        have_recent_netmap="no"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #include <net/netmap_user.h>
        ],[
        #ifndef NETMAP_API
        #error "outdated netmap, need one with NETMAP_API"
        #endif
        #if NETMAP_API < 11
        #error "outdated netmap, need at least api version 11"
        #endif
        ])], [have_recent_netmap="yes"])
        if test "x$have_recent_netmap" != "xyes"; then
            echo "ERROR: outdated netmap"
            exit 1
        fi
        have_netmap_version="unknown"
        have_v11_netmap="no"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #include <net/netmap_user.h>
        ],[
        #if NETMAP_API != 11
        #error "not 11"
        #endif
        ])], [have_v11_netmap="yes"])
        if test "x$have_v11_netmap" = "xyes"; then
            have_netmap_version="v11"
        fi
        have_v12_netmap="no"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #include <net/netmap_user.h>
        ],[
        #if NETMAP_API != 12
        #error "not 12"
        #endif
        ])], [have_v12_netmap="yes"])
        if test "x$have_v12_netmap" = "xyes"; then
            have_netmap_version="v12"
        fi
        have_v13_netmap="no"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #include <net/netmap_user.h>
        ],[
        #if NETMAP_API != 13
        #error "not 13"
        #endif
        ])], [have_v13_netmap="yes"])
        if test "x$have_v13_netmap" = "xyes"; then
            have_netmap_version="v13"
        fi
        have_gtv13_netmap="no"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #include <net/netmap_user.h>
        ],[
        #if NETMAP_API <= 13
        #error "not gt 13"
        #endif
        ])], [have_gtv13_netmap="yes"])
        if test "x$have_gtv13_netmap" = "xyes"; then
            have_netmap_version="> v13"
        fi
  ])

  # Suricata-Update.
    AC_ARG_ENABLE([suricata-update], AS_HELP_STRING([--disable-suricata-update],
        [Disable suricata-update]), [enable_suricata_update=$enableval],
      [enable_suricata_update="yes"])

    # Assume suircata-update will not be installed.
    have_suricata_update="no"
    ruledirprefix="$sysconfdir"

    if test "$enable_suricata_update" = "yes"; then
        if test -f "$srcdir/suricata-update/setup.py"; then
          have_suricata_update="yes"
	fi
    fi

    if test "$have_suricata_update" = "yes"; then
        if test "$have_python_yaml" != "yes"; then
	    echo ""
	    echo "    Warning: suricata-update will not be installed as the"
	    echo "        Python yaml module is not installed.."
	    echo ""
            echo "    Install the yaml module for Python ${pymv} to enable"
            echo "    suricata-update."
	    echo
	else
            SURICATA_UPDATE_DIR="suricata-update"
            AC_SUBST(SURICATA_UPDATE_DIR)
            AC_CONFIG_FILES(suricata-update/Makefile)
            AC_OUTPUT
            ruledirprefix="$localstatedir/lib"
	fi
    fi

    # Test to see if suricatactl (and suricatasc) can be installed.
    if test "x$enable_python" != "xyes"; then
        install_suricatactl="requires python"
    elif test "x$have_python_distutils" != "xyes"; then
        install_suricatactl="no, requires distutils"
    else
        install_suricatactl="yes"
    fi

    # Test to see if suricata-update can be installed.
    if test "x$have_suricata_update" != "xyes"; then
        install_suricata_update="not bundled"
    elif test "x$enable_python" != "xyes"; then
        install_suricata_update="no, requires python"
    elif test "x$have_python_distutils" != "xyes"; then
        install_suricata_update="no, requires distutils"
    elif test "x$have_python_yaml" != "xyes"; then
        install_suricata_update="no, requires pyyaml"
    else
        install_suricata_update="yes"
    fi

    AM_CONDITIONAL([INSTALL_SURICATA_UPDATE],
        [test "x$install_suricata_update" = "xyes"])

  # libhtp
    AC_ARG_ENABLE(non-bundled-htp,
           AS_HELP_STRING([--enable-non-bundled-htp], [Enable the use of an already installed version of htp]),[enable_non_bundled_htp=$enableval],[enable_non_bundled_htp=no])
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

        AC_CHECK_HEADER(htp/htp.h,,[AC_MSG_ERROR(htp/htp.h not found ...)])

        LIBHTP=""
        AC_CHECK_LIB(htp, htp_conn_create,, LIBHTP="no")
        if test "$LIBHTP" = "no"; then
            echo
            echo "   ERROR! libhtp library not found"
            echo
            exit 1
        fi
        PKG_CHECK_MODULES(LIBHTPMINVERSION, [htp >= 0.5.40],[libhtp_minver_found="yes"],[libhtp_minver_found="no"])
        if test "$libhtp_minver_found" = "no"; then
            PKG_CHECK_MODULES(LIBHTPDEVVERSION, [htp = 0.5.X],[libhtp_devver_found="yes"],[libhtp_devver_found="no"])
            if test "$libhtp_devver_found" = "no"; then
                echo
                echo "   ERROR! libhtp was found but it is neither >= 0.5.40, nor the dev 0.5.X"
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
        AC_CHECK_LIB([htp], [htp_config_set_lzma_memlimit],AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_LZMA_MEMLIMIT],[1],[Found htp_config_set_lzma_memlimit function in libhtp]) ,,[-lhtp])
        AC_CHECK_LIB([htp], [htp_config_set_lzma_layers],AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_LZMA_LAYERS],[1],[Found htp_config_set_lzma_layers function in libhtp]) ,,[-lhtp])
        AC_CHECK_LIB([htp], [htp_config_set_compression_bomb_limit],AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_COMPRESSION_BOMB_LIMIT],[1],[Found htp_config_set_compression_bomb_limit function in libhtp]) ,,[-lhtp])
        AC_CHECK_LIB([htp], [htp_config_set_compression_time_limit],AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_COMPRESSION_TIME_LIMIT],[1],[Found htp_config_set_compression_time_limit function in libhtp]) ,,[-lhtp])
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

            AC_CHECK_HEADER(iconv.h,,[AC_MSG_ERROR(iconv.h not found ...)])
            AC_CHECK_LIB(iconv, libiconv_close)
            AC_DEFINE_UNQUOTED([HAVE_HTP_URI_NORMALIZE_HOOK],[1],[Assuming htp_config_register_request_uri_normalize function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW],[1],[Assuming htp_tx_get_response_headers_raw function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_DECODE_QUERY_INPLACE],[1],[Assuming htp_decode_query_inplace function in bundled libhtp])
            # enable when libhtp has been updated
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT],[1],[Assuming htp_config_set_response_decompression_layer_limit function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_LZMA_MEMLIMIT],[1],[Assuming htp_config_set_lzma_memlimit function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_LZMA_LAYERS],[1],[Assuming htp_config_set_lzma_layers function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_COMPRESSION_BOMB_LIMIT],[1],[Assuming htp_config_set_compression_bomb_limit function in bundled libhtp])
            AC_DEFINE_UNQUOTED([HAVE_HTP_CONFIG_SET_COMPRESSION_TIME_LIMIT],[1],[Assuming htp_config_set_compression_time_limit function in bundled libhtp])
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
        echo "   Fedora: dnf install libcap-ng-devel"
        echo "   CentOS/RHEL: yum install libcap-ng-devel"
        echo
        echo "   Suricata will be built without support for dropping privs."
        echo
    fi
    ;;
    esac

    AC_ARG_ENABLE(unwind,
            AS_HELP_STRING([--enable-unwind], [Enable unwind support]),[enable_unwind=$enableval],[enable_unwind=no])
    AS_IF([test "x$enable_unwind" = "xyes"], [
        AC_CHECK_LIB(unwind,unw_backtrace,,LIBUNW="no")
        if test "$LIBUNW" = "no"; then
            echo
            echo "   libunwind library and development headers not found"
            echo "   stacktrace on unexpected termination due to signal not possible"
            echo
        fi;
        ])

    AC_ARG_ENABLE(ebpf,
	        AS_HELP_STRING([--enable-ebpf],[Enable eBPF support]),
	        [ enable_ebpf="$enableval"],
	        [ enable_ebpf="no"])

    have_xdp="no"
    if test "$enable_ebpf" = "yes"; then
        AC_CHECK_LIB(elf,elf_begin,,LIBELF="no")
        if test "$LIBELF" = "no"; then
            echo
            echo "   libelf library and development headers not found but"
            echo "   but needed to use eBPF code"
            echo
            exit 1
        fi;

        AC_CHECK_LIB(bpf,bpf_object__open,,LIBBPF="no")
        if test "$LIBBPF" = "no"; then
            echo
            echo "   libbpf library and development headers not found but"
            echo "   needed to use eBPF code. It can be found at"
            echo "   https://github.com/libbpf/libbpf"
            echo
            exit 1
        fi;
        AC_CHECK_DECL([PACKET_FANOUT_EBPF],
            AC_DEFINE([HAVE_PACKET_EBPF],[1],[Recent ebpf fanout support is available]),
            [],
            [[#include <linux/if_packet.h>]])
        AC_CHECK_LIB(bpf, bpf_set_link_xdp_fd,have_xdp="yes")
        if test "$have_xdp" = "yes"; then
            AC_DEFINE([HAVE_PACKET_XDP],[1],[XDP support is available])
        fi
        AC_CHECK_FUNCS(bpf_program__section_name)
    fi;

  # Check for DAG support.
    AC_ARG_ENABLE(dag,
	        AS_HELP_STRING([--enable-dag],[Enable DAG capture]),
	        [ enable_dag=$enableval ],
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

# libnspr (enabled by default)
    AC_ARG_ENABLE(nspr,
            AS_HELP_STRING([--disable-nspr],[Disable libnspr support]),
            [enable_nspr=$enableval],[enable_nspr="yes"])

    AC_ARG_WITH(libnspr_includes,
            [  --with-libnspr-includes=DIR  libnspr include directory],
            [with_libnspr_includes="$withval"],[with_libnspr_includes="no"])

    AC_ARG_WITH(libnspr_libraries,
            [  --with-libnspr-libraries=DIR    libnspr library directory],
            [with_libnspr_libraries="$withval"],[with_libnspr_libraries="no"])

    if test "$enable_nspr" != "no"; then
        # Try pkg-config first:
        PKG_CHECK_MODULES([libnspr],nspr,,[with_pkgconfig_nspr="no"])

        if test "$with_pkgconfig_nspr" != "no"; then
            CPPFLAGS="${CPPFLAGS} ${libnspr_CFLAGS}"
            LIBS="${LIBS} ${libnspr_LIBS}"
        fi

        if test "$with_libnspr_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libnspr_includes}"
        fi
        TMPLIBS="${LIBS}"
        AC_CHECK_HEADER(nspr.h,
           AC_CHECK_LIB(nspr4,PR_GetCurrentThread,[AC_DEFINE([HAVE_NSPR],[1],[libnspr available])
           NSPR="yes"
            if test "$NSPR" = "yes"; then
                if test "$with_libnspr_libraries" != "no"; then
                    LDFLAGS="${LDFLAGS}  -L${with_libnspr_libraries}"
                   LIBS="${TMPLIBS}"
                else
                   LIBS="${TMPLIBS}"
                fi
            fi]),NSPR="no")

        if test "$NSPR" = "no"; then
            echo
            echo "   libnspr library not found, go get it"
            echo "   from Mozilla or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libnspr4-dev"
            echo "   Fedora: dnf install nspr-devel"
            echo "   CentOS/RHEL: yum install nspr-devel"
            echo
            enable_nspr="no"
        fi
    fi

  # libnss (enabled by default)

    AC_ARG_ENABLE(nss,
            AS_HELP_STRING([--disable-nss],[Disable libnss support]),
            [enable_nss=$enableval],[enable_nss="yes"])

    AC_ARG_WITH(libnss_includes,
            [  --with-libnss-includes=DIR  libnss include directory],
            [with_libnss_includes="$withval"],[with_libnss_includes="no"])

    AC_ARG_WITH(libnss_libraries,
            [  --with-libnss-libraries=DIR    libnss library directory],
            [with_libnss_libraries="$withval"],[with_libnss_libraries="no"])

    if test "$enable_nss" != "no"; then
        # Try pkg-config first:
        PKG_CHECK_MODULES([libnss],nss,,[with_pkgconfig_nss="no"])

        if test "$with_pkgconfig_nss" != "no"; then
            CPPFLAGS="${CPPFLAGS} ${libnss_CFLAGS}"
            LIBS="${LIBS} ${libnss_LIBS}"
        fi

        if test "$with_libnss_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libnss_includes}"
        fi
        TMPLIBS="${LIBS}"

        AC_CHECK_HEADER(sechash.h,
            AC_CHECK_LIB(nss3,HASH_Begin,[AC_DEFINE([HAVE_NSS],[1],[libnss available])
            NSS="yes"
           if test "$NSS" = "yes"; then
                if test "$with_libnss_libraries" != "no"; then
                    LDFLAGS="${LDFLAGS}  -L${with_libnss_libraries}"
                   LIBS="${TMPLIBS}"
               else
                   LIBS="${TMPLIBS}"
                fi
           fi]),NSS="no")

        if test "$NSS" = "no"; then
            echo
            echo "   libnss library not found, go get it"
            echo "   from Mozilla or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libnss3-dev"
            echo "   Fedora: dnf install nss-devel"
            echo "   CentOS/RHEL: yum install nss-devel"
            echo
            enable_nss="no"
        fi
    fi

  # libmagic
    enable_magic="no"
    AC_ARG_ENABLE(libmagic,
           AS_HELP_STRING([--enable-libmagic], [Enable libmagic support [default=yes]]),
                        [enable_magic=$enableval],[enable_magic=yes])
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
            echo "   Fedora: dnf install file-devel"
            echo "   CentOS/RHEL: yum install file-devel"
            echo
            enable_magic="no"
        fi
    fi

    # Napatech - Using the 3GD API
    AC_ARG_ENABLE(napatech,
                AS_HELP_STRING([--enable-napatech],[Enabled Napatech Devices]),
                [ enable_napatech=$enableval ],
                [ enable_napatech=no])
    AC_ARG_ENABLE(napatech_bypass,
                AS_HELP_STRING([--disable-napatech-bypass],[Disable Bypass feature on Napatech cards]),
                [ napatech_bypass=$enableval ],
                [ napatech_bypass=yes])
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
        else
            AC_CHECK_LIB(numa, numa_available,, LIBNUMA="no")
            if test "$LIBNUMA" = "no"; then
                echo
                echo "  WARNING: libnuma is required to use Napatech auto-config"
                echo "      libnuma is not found.  Go get it"
                echo "      from http://github.com/numactl/numactl or your distribution:"
                echo "          Ubuntu: apt-get install libnuma-dev"
                echo "          Fedora: dnf install numactl-devel"
                echo "          CentOS/RHEL: yum install numactl-devel"
                echo
                exit 1
            fi
        fi

        AC_DEFINE([HAVE_NAPATECH],[1],(Napatech capture card support))
        if test "$napatech_bypass" = "yes"; then
            AC_CHECK_LIB(ntapi, NT_FlowOpenAttrInit,NTFLOW="yes",NTFLOW="no")
            if test "$NTFLOW" = "yes"; then
                echo "   Napatech Flow Processing is Enabled (--disable-napatech-bypass if not needed)"
                AC_DEFINE([NAPATECH_ENABLE_BYPASS],[1],(Napatech flowdirector support))
            else
                echo "Napatech Flow Processing is not available"
            fi
        else
            echo "Napatech Flow Processing is Disabled."
        fi
    fi

  # liblua
    AC_ARG_ENABLE(lua,
	        AS_HELP_STRING([--enable-lua],[Enable Lua support]),
	        [ enable_lua="$enableval"],
	        [ enable_lua="no"])
    AC_ARG_ENABLE(luajit,
	        AS_HELP_STRING([--enable-luajit],[Enable Luajit support]),
	        [ enable_luajit="$enableval"],
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
                    echo "   Fedora: dnf install lua-devel"
                    echo "   CentOS/RHEL: yum install lua-devel"
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
                echo "   Fedora: dnf install lua-devel"
                echo "   CentOS/RHEL: yum install lua-devel"
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

    # If Lua is enabled, test the integer size.
    if test "x$enable_lua" = "xyes" -a "$cross_compiling" != "yes"; then
        TMPLIBS="$LIBS"
        LIBS=""

        AC_MSG_CHECKING([size of lua integer])
        AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <lua.h>]],
            [[
            if (sizeof(lua_Integer) == 8) {
                return 1;
            }
            return 0;
            ]])],
            [
                AC_MSG_RESULT([4])
            ],
            [
                AC_MSG_RESULT([8])
                AC_SUBST([LUA_INT8], ["lua_int8"])
            ])
        LIBS="$TMPLIBS"
    fi

  # libmaxminddb
    AC_ARG_ENABLE(geoip,
	        AS_HELP_STRING([--enable-geoip],[Enable GeoIP2 support]),
	        [ enable_geoip="$enableval"],
	        [ enable_geoip="no"])
    AC_ARG_WITH(libmaxminddb_includes,
            [  --with-libmaxminddb-includes=DIR  libmaxminddb include directory],
            [with_libmaxminddb_includes="$withval"],[with_libmaxminddb_includes="no"])
    AC_ARG_WITH(libmaxminddb_libraries,
            [  --with-libmaxminddb-libraries=DIR    libmaxminddb library directory],
            [with_libmaxminddb_libraries="$withval"],[with_libmaxminddb_libraries="no"])

    if test "$enable_geoip" = "yes"; then
        if test "$with_libmaxminddb_includes" != "no"; then
            CPPFLAGS="${CPPFLAGS} -I${with_libmaxminddb_includes}"
        fi

        AC_CHECK_HEADER(maxminddb.h,GEOIP="yes",GEOIP="no")
        if test "$GEOIP" = "yes"; then
            if test "$with_libmaxminddb_libraries" != "no"; then
                LDFLAGS="${LDFLAGS} -L${with_libmaxminddb_libraries}"
            fi
            AC_CHECK_LIB(maxminddb, MMDB_open,, GEOIP="no")
        fi
        if test "$GEOIP" = "no"; then
            echo
            echo "   ERROR!  libmaxminddb GeoIP2 library not found, go get it"
            echo "   from https://github.com/maxmind/libmaxminddb or your distribution:"
            echo
            echo "   Ubuntu: apt-get install libmaxminddb-dev"
            echo "   Fedora: dnf install libmaxminddb-devel"
            echo "   CentOS/RHEL: yum install libmaxminddb-devel"
            echo
            exit 1
        fi

        AC_DEFINE([HAVE_GEOIP],[1],[libmaxminddb available])
        enable_geoip="yes"
    fi

  # Position Independent Executable
    AC_ARG_ENABLE(pie,
                AS_HELP_STRING([--enable-pie],[Enable compiling as a position independent executable]),
                [ enable_pie="$enableval"],
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
	        [ enable_hiredis="$enableval"],
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
            echo "   CentOS/RHEL: yum install hiredis-devel"
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
                if [ test "$HAVE_LIBEVENT" = "no" ] && [ -o test "$HAVE_LIBEVENT_PTHREADS" = "no"]; then
                    if test "$HAVE_LIBEVENT" = "no"; then
                        echo
                        echo "  Async mode for redis output will not be available."
                        echo "  To enable it install libevent"
                        echo
                        echo "   Ubuntu: apt-get install libevent-dev"
                        echo "   Fedora: dnf install libevent-devel"
                        echo "   CentOS/RHEL: yum install libevent-devel"
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

# Check for lz4
enable_liblz4="yes"
AC_CHECK_LIB(lz4, LZ4F_createCompressionContext, , enable_liblz4="no")

if test "$enable_liblz4" = "no"; then
    echo
    echo "  Compressed pcap logging is not available without liblz4."
    echo "  If you want to enable compression, you need to install it."
    echo
    echo "  Ubuntu: apt-get install liblz4-dev"
    echo "  Fedora: dnf install lz4-devel"
    echo "  CentOS/RHEL: yum install epel-release"
    echo "               yum install lz4-devel"
    echo
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

# Cargo/Rust
    AM_CONDITIONAL([RUST_CROSS_COMPILE], [test "x$cross_compiling" = "xyes"])
    AC_PATH_PROG(RUSTC, rustc, "no")
    if test "$RUSTC" = "no"; then
        echo ""
        echo "    ERROR: Suricata now requires Rust to build."
        echo ""
        echo "    Ubuntu/Debian: apt install rustc cargo"
        echo "    Fedora: dnf install rustc cargo"
        echo "    CentOS: yum install rustc cargo (requires EPEL)"
        echo ""
        echo "    Rustup works as well: https://rustup.rs/"
        echo ""
        exit 1
    fi

    AC_PATH_PROG(CARGO, cargo, "no")
    if test "CARGO" = "no"; then
        AC_MSG_ERROR([cargo required])
    fi

    AC_DEFINE([HAVE_RUST],[1],[Enable Rust language])
    AM_CONDITIONAL([HAVE_RUST],true)
    AC_SUBST([CARGO], [$CARGO])

    enable_rust="yes"
    rust_compiler_version=$($RUSTC --version)
    rustc_version=$(echo "$rust_compiler_version" | sed 's/^.*[[^0-9]]\([[0-9]]*\.[[0-9]]*\.[[0-9]]*\).*$/\1/')
    cargo_version_output=$($CARGO --version)
    cargo_version=$(echo "$cargo_version_output" | sed 's/^.*[[^0-9]]\([[0-9]]*\.[[0-9]]*\.[[0-9]]*\).*$/\1/')

    MIN_RUSTC_VERSION="1.41.1"
    AC_MSG_CHECKING(for Rust version $MIN_RUSTC_VERSION or newer)
    AS_VERSION_COMPARE([$rustc_version], [$MIN_RUSTC_VERSION],
        [
            echo ""
            echo "ERROR: Rust $MIN_RUSTC_VERSION or newer required."
            echo ""
            echo "Rust version ${rustc_version} was found."
            echo ""
            exit 1
	],
	[],
	[])
    AC_MSG_RESULT(yes)

    RUST_FEATURES=""
    AS_VERSION_COMPARE([$rustc_version], [1.38.0],
        [],
	[RUST_FEATURES="$RUST_FEATURES function-macro"],
	[RUST_FEATURES="$RUST_FEATURES function-macro"])

    rust_vendor_comment="# "
    have_rust_vendor="no"

    if test "x$cross_compiling" = "xyes"; then
      RUST_SURICATA_LIB_XC_DIR="${host_alias}/"
    else
      if test "x$CARGO_BUILD_TARGET" = "x"; then
        RUST_SURICATA_LIB_XC_DIR=
      else
        RUST_SURICATA_LIB_XC_DIR="${CARGO_BUILD_TARGET}/"
      fi
    fi

    if test "x$enable_debug" = "xyes"; then
      RUST_SURICATA_LIBDIR="../rust/target/${RUST_SURICATA_LIB_XC_DIR}debug"
    else
      RUST_SURICATA_LIBDIR="../rust/target/${RUST_SURICATA_LIB_XC_DIR}release"
    fi
    RUST_SURICATA_LIB="${RUST_SURICATA_LIBDIR}/${RUST_SURICATA_LIBNAME}"

    RUST_LDADD="${RUST_SURICATA_LIB} ${RUST_LDADD}"
    CFLAGS="${CFLAGS} -I\${srcdir}/../rust/gen -I\${srcdir}/../rust/dist"
    AC_SUBST(RUST_SURICATA_LIB)
    AC_SUBST(RUST_LDADD)
    if test "x$CARGO_HOME" = "x"; then
        if test "x$HAVE_CYGPATH" != "xno"; then
          CYGPATH_CARGO_HOME=$(cygpath -a -t mixed ~/.cargo)
          AC_SUBST([CARGO_HOME], [$CYGPATH_CARGO_HOME])
        else
          AC_SUBST([CARGO_HOME], [~/.cargo])
        fi
    else
      AC_SUBST([CARGO_HOME], [$CARGO_HOME])
    fi

    # Check for rustup. RUSTUP_HOME needs to be set if rustup is in
    # use, and a user uses sudo (depending on configuration), or su to
    # perform the install
    rustup_home_path="no"
    if test "x$RUSTUP_HOME" != "x"; then
        rustup_home_path="$RUSTUP_HOME"
    else
        AC_PATH_PROG(have_rustup, rustup, "no")
        if test "x$have_rustup" != "xno"; then
            rustup_home_path=$($have_rustup show home 2>/dev/null || echo "no")
        fi
    fi
    rustup_home=""
    if test "x$rustup_home_path" != "xno"; then
        rustup_home="RUSTUP_HOME=\$(RUSTUP_HOME_PATH)"
    fi
    AC_SUBST([RUSTUP_HOME_PATH], [$rustup_home_path])
    AC_SUBST([rustup_home])

    if test -e "$srcdir/rust/vendor"; then
      have_rust_vendor="yes"
    fi

    if test "x$have_rust_vendor" = "xyes"; then
      rust_vendor_comment=""
    fi

    AC_SUBST(rust_vendor_comment)
    AM_CONDITIONAL([HAVE_RUST_VENDOR], [test "x$have_rust_vendor" = "xyes"])

    # With Rust/Cargo 1.37 and greater, cargo-vendor is built-in.
    AC_MSG_CHECKING(for cargo vendor support)
    AS_VERSION_COMPARE([$cargo_version], [1.37.0],
        [have_cargo_vendor="no"],
        [have_cargo_vendor="yes"],
        [have_cargo_vendor="yes"])
    AC_MSG_RESULT($have_cargo_vendor)

    # If Rust is older than 1.37, check for cargo-vendor as an
    # external sub-command.
    if test "x$have_cargo_vendor" != "xyes"; then
        AC_CHECK_PROG(have_cargo_vendor_bin, cargo-vendor, yes, no)
        have_cargo_vendor=$have_cargo_vendor_bin
    fi

    have_rust_headers="no"
    AC_MSG_CHECKING(for $srcdir/rust/dist/rust-bindings.h)
    if test -f "$srcdir/rust/dist/rust-bindings.h"; then
       AC_MSG_RESULT(yes)
       have_rust_headers="yes"
    else
       AC_MSG_RESULT(no)
       AC_MSG_CHECKING(for $srcdir/rust/gen/rust-bindings.h)
       if test -f "$srcdir/rust/gen/rust-bindings.h"; then
           AC_MSG_RESULT(yes)
           have_rust_headers="yes"
       else
           AC_MSG_RESULT(no)
       fi
    fi

    AC_PATH_PROG(CBINDGEN, cbindgen, "no")
    if test "x$CBINDGEN" != "xno"; then
      cbindgen_version=$(cbindgen --version | cut -d' ' -f2-)
      min_cbindgen_version="0.10.0"
      AS_VERSION_COMPARE([$cbindgen_version], [$min_cbindgen_version],
          [cbindgen_ok="no"],
          [cbindgen_ok="yes"],
          [cbindgen_ok="yes"])
      if test "x$cbindgen_ok" != "xyes"; then
        echo "  Warning: cbindgen must be at least version $min_cbindgen_version,"
        echo "      found $cbindgen_version."
        echo "  To update: cargo install --force cbindgen"
        CBINDGEN="no"
      else
        have_rust_headers="no"
      fi
    fi

    AC_SUBST([CBINDGEN], [$CBINDGEN])

    # Require cbindgen if generated headers are not bundled.
    if test "x$have_rust_headers" != "xyes"; then
      if test "x$CBINDGEN" = "xno"; then
        echo "  Warning: cbindgen too old or not found, it is required to "
        echo "      generate header files."
        echo "  To install: cargo install --force cbindgen"
        AC_MSG_ERROR([cbindgen required])
      fi
    fi

    AM_CONDITIONAL([HAVE_RUST_HEADERS], [test "x$have_rust_headers" = "xyes"])
    AM_CONDITIONAL([HAVE_CBINDGEN], [test "x$CBINDGEN" != "xno"])
    AM_CONDITIONAL([HAVE_CARGO_VENDOR], [test "x$have_cargo_vendor" != "xno"])

    AC_ARG_ENABLE(rust_strict,
           AS_HELP_STRING([--enable-rust-strict], [Rust warnings as errors]),[enable_rust_strict=$enableval],[enable_rust_strict=no])
    AS_IF([test "x$enable_rust_strict" = "xyes"], [
        RUST_FEATURES="strict"
    ])
    AC_SUBST(RUST_FEATURES)

    AC_ARG_ENABLE(fuzztargets,
        AS_HELP_STRING([--enable-fuzztargets], [Enable fuzz targets]),[enable_fuzztargets=$enableval],[enable_fuzztargets=no])
    AM_CONDITIONAL([BUILD_FUZZTARGETS], [test "x$enable_fuzztargets" = "xyes"])
    AM_CONDITIONAL([RUST_BUILD_STD], [test "x$enable_fuzztargets" = "xyes" && echo "$rust_compiler_version" | grep -q nightly && echo "$RUSTFLAGS" | grep -v -q coverage])
    AC_PROG_CXX
    AS_IF([test "x$enable_fuzztargets" = "xyes"], [
        AS_IF([test "x$CARGO_BUILD_TARGET" = "x" && echo "$rust_compiler_version" | grep -q nightly], [
            CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu
            AC_SUBST(CARGO_BUILD_TARGET)
        ])
        AC_DEFINE([FUZZ], [1], [Fuzz targets are enabled])
        AC_DEFINE([AFLFUZZ_NO_RANDOM], [1], [Disable all use of random functions])
        CFLAGS_ORIG=$CFLAGS
        CFLAGS="-Werror"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[while (__AFL_LOOP(1000))]])],
                [AC_DEFINE([AFLFUZZ_PERSISTANT_MODE], [1], [Enable AFL PERSISTANT_MODE])],
                [])
        CFLAGS=$CFLAGS_ORIG
        AC_LANG_PUSH(C++)
        tmp_saved_flags=$[]_AC_LANG_PREFIX[]FLAGS
        AS_IF([test "x$LIB_FUZZING_ENGINE" = "x"], [
            LIB_FUZZING_ENGINE=-fsanitize=fuzzer
            AC_SUBST(LIB_FUZZING_ENGINE)
        ])
        _AC_LANG_PREFIX[]FLAGS="$[]_AC_LANG_PREFIX[]FLAGS $LIB_FUZZING_ENGINE"
        AC_MSG_CHECKING([whether $CXX accepts $LIB_FUZZING_ENGINE])
        AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size);
extern "C" int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size) {
(void)Data;
(void)Size;
return 0;
}
            ]])],
            [ AC_MSG_RESULT(yes)
              has_sanitizefuzzer=yes],
            [ AC_MSG_RESULT(no) ]
        )
        _AC_LANG_PREFIX[]FLAGS=$tmp_saved_flags
        AC_LANG_POP()
    ])

    AM_CONDITIONAL([HAS_FUZZLDFLAGS], [test "x$has_sanitizefuzzer" = "xyes"])

# get revision
    if test -f ./revision; then
        REVISION=`cat ./revision`
        AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
    else
        AC_PATH_PROG(HAVE_GIT_CMD, git, "no")
        if test "$HAVE_GIT_CMD" != "no"; then
            if [ test -d .git ]; then
                REVISION=`git rev-parse --short HEAD`
                DATE=`git log -1 --date=short --pretty=format:%cd`
                REVISION="$REVISION $DATE"
                AC_DEFINE_UNQUOTED([REVISION],[${REVISION}],[Git revision])
            fi
        fi
    fi

if test "${enable_ebpf}" = "yes" || test "${enable_unittests}" = "yes"; then
  AC_DEFINE([CAPTURE_OFFLOAD_MANAGER], [1],[Building flow bypass manager code])
fi
if test "${enable_ebpf}" = "yes" || test "${enable_nfqueue}" = "yes" || test "${enable_pfring}" = "yes" || test "${enable_napatech}" = "yes"  || test "${enable_unittests}" = "yes"; then
  AC_DEFINE([CAPTURE_OFFLOAD], [1],[Building flow capture bypass code])
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
    case $host in
        x86_64-w64-mingw32)
            e_winbase="C:\\\\Program Files\\\\Suricata"
            ;;
        *)
            systemtype="`systeminfo | grep \"based PC\"`"
            case "$systemtype" in
            *x64*)
                e_winbase="C:\\\\Program Files (x86)\\\\Suricata"
                ;;
            *)
                e_winbase="C:\\\\Program Files\\\\Suricata"
                ;;
        esac
    esac

    e_sysconfdir="${e_winbase}\\\\"
    e_defaultruledir="$e_winbase\\\\rules\\\\"
    e_magic_file="$e_winbase\\\\magic.mgc"
    e_logdir="$e_winbase\\\\log"
    e_logfilesdir="$e_logdir\\\\files"
    e_logcertsdir="$e_logdir\\\\certs"
    e_datarulesdir="$e_winbase\\\\rules\\\\"
    if test "x$HAVE_CYGPATH" != "xno"; then
        # turn srcdir into abs path and convert to the
        # mixed output (/c/Users/dev into  c:/Users/dev)
        e_rustdir="$(cygpath -a -t mixed ${srcdir})/rust"
    else
        e_abs_srcdir=$(cd $srcdir && pwd)
        e_rustdir="$e_abs_srcdir/rust"
    fi
else
    EXPAND_VARIABLE(localstatedir, e_logdir, "/log/suricata/")
    EXPAND_VARIABLE(localstatedir, e_rundir, "/run/")
    EXPAND_VARIABLE(localstatedir, e_logfilesdir, "/log/suricata/files")
    EXPAND_VARIABLE(localstatedir, e_logcertsdir, "/log/suricata/certs")
    EXPAND_VARIABLE(sysconfdir, e_sysconfdir, "/suricata/")
    EXPAND_VARIABLE(localstatedir, e_localstatedir, "/run/suricata")
    EXPAND_VARIABLE(datadir, e_datarulesdir, "/suricata/rules")
    EXPAND_VARIABLE(localstatedir, e_datadir, "/lib/suricata/data")
    EXPAND_VARIABLE(ruledirprefix, e_defaultruledir, "/suricata/rules")

    e_abs_srcdir=$(cd $srcdir && pwd)
    EXPAND_VARIABLE(e_abs_srcdir, e_rustdir, "/rust")
fi
AC_SUBST(e_logdir)
AC_SUBST(e_rundir)
AC_SUBST(e_logfilesdir)
AC_SUBST(e_logcertsdir)
AC_SUBST(e_sysconfdir)
AC_DEFINE_UNQUOTED([CONFIG_DIR],["$e_sysconfdir"],[Our CONFIG_DIR])
AC_SUBST(e_localstatedir)
AC_DEFINE_UNQUOTED([DATA_DIR],["$e_datadir"],[Our DATA_DIR])
AC_SUBST(e_magic_file)
AC_SUBST(e_magic_file_comment)
AC_SUBST(e_enable_evelog)
AC_SUBST(e_datarulesdir)
AC_SUBST(e_defaultruledir)
AC_SUBST(e_rustdir)

EXPAND_VARIABLE(prefix, CONFIGURE_PREFIX)
EXPAND_VARIABLE(sysconfdir, CONFIGURE_SYSCONDIR)
EXPAND_VARIABLE(localstatedir, CONFIGURE_LOCALSTATEDIR)
EXPAND_VARIABLE(datadir, CONFIGURE_DATAROOTDIR)
AC_SUBST(CONFIGURE_PREFIX)
AC_SUBST(CONFIGURE_SYSCONDIR)
AC_SUBST(CONFIGURE_LOCALSTATEDIR)
AC_SUBST(CONFIGURE_DATAROOTDIR)
AC_SUBST(PACKAGE_VERSION)
AC_SUBST(RUST_FEATURES)
AC_SUBST(RUST_SURICATA_LIBDIR)

AC_CONFIG_FILES(Makefile src/Makefile rust/Makefile rust/Cargo.toml rust/.cargo/config)
AC_CONFIG_FILES(qa/Makefile qa/coccinelle/Makefile)
AC_CONFIG_FILES(rules/Makefile doc/Makefile doc/userguide/Makefile doc/devguide/Makefile)
AC_CONFIG_FILES(contrib/Makefile contrib/file_processor/Makefile contrib/file_processor/Action/Makefile contrib/file_processor/Processor/Makefile)
AC_CONFIG_FILES(suricata.yaml etc/Makefile etc/suricata.logrotate etc/suricata.service)
AC_CONFIG_FILES(python/Makefile python/suricata/config/defaults.py)
AC_CONFIG_FILES(ebpf/Makefile)
AC_OUTPUT

SURICATA_BUILD_CONF="Suricata Configuration:
  AF_PACKET support:                       ${enable_af_packet}
  eBPF support:                            ${enable_ebpf}
  XDP support:                             ${have_xdp}
  PF_RING support:                         ${enable_pfring}
  NFQueue support:                         ${enable_nfqueue}
  NFLOG support:                           ${enable_nflog}
  IPFW support:                            ${enable_ipfw}
  Netmap support:                          ${enable_netmap} ${have_netmap_version}
  DAG enabled:                             ${enable_dag}
  Napatech enabled:                        ${enable_napatech}
  WinDivert enabled:                       ${enable_windivert}

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
  GeoIP2 support:                          ${enable_geoip}
  Non-bundled htp:                         ${enable_non_bundled_htp}
  Hyperscan support:                       ${enable_hyperscan}
  Libnet support:                          ${enable_libnet}
  liblz4 support:                          ${enable_liblz4}
  HTTP2 decompression:                     ${enable_http2_decompression}

  Rust support:                            ${enable_rust}
  Rust strict mode:                        ${enable_rust_strict}
  Rust compiler path:                      ${RUSTC}
  Rust compiler version:                   ${rust_compiler_version}
  Cargo path:                              ${CARGO}
  Cargo version:                           ${cargo_version_output}
  Cargo vendor:                            ${have_cargo_vendor}

  Python support:                          ${enable_python}
  Python path:                             ${python_path}
  Python distutils                         ${have_python_distutils}
  Python yaml                              ${have_python_yaml}
  Install suricatactl:                     ${install_suricatactl}
  Install suricatasc:                      ${install_suricatactl}
  Install suricata-update:                 ${install_suricata_update}

  Profiling enabled:                       ${enable_profiling}
  Profiling locks enabled:                 ${enable_profiling_locks}

  Plugin support (experimental):           ${plugin_support}

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
  --datarootdir                            ${CONFIGURE_DATAROOTDIR}

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

