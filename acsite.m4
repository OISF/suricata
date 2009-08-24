#These defines are needed because CentOS5 uses a old version of autoconf
#
AC_DEFUN([AC_TYPE_INT8_T], [_AC_TYPE_INT(8)])
AC_DEFUN([AC_TYPE_INT16_T], [_AC_TYPE_INT(16)])
AC_DEFUN([AC_TYPE_INT32_T], [_AC_TYPE_INT(32)])
AC_DEFUN([AC_TYPE_INT64_T], [_AC_TYPE_INT(64)])
AC_DEFUN([AC_TYPE_UINT8_T], [_AC_TYPE_UNSIGNED_INT(8)])
AC_DEFUN([AC_TYPE_UINT16_T], [_AC_TYPE_UNSIGNED_INT(16)])
AC_DEFUN([AC_TYPE_UINT32_T], [_AC_TYPE_UNSIGNED_INT(32)])
AC_DEFUN([AC_TYPE_UINT64_T], [_AC_TYPE_UNSIGNED_INT(64)])

# _AC_TYPE_INT(NBITS)
# -------------------
AC_DEFUN([_AC_TYPE_INT],
[
  AC_CACHE_CHECK([for int$1_t], [ac_cv_c_int$1_t],
    [ac_cv_c_int$1_t=no
     for ac_type in 'int$1_t' 'int' 'long int' \
	 'long long int' 'short int' 'signed char'; do
       AC_COMPILE_IFELSE(
	 [AC_LANG_BOOL_COMPILE_TRY(
	    [AC_INCLUDES_DEFAULT],
	    [[0 < ($ac_type) (((($ac_type) 1 << ($1 - 2)) - 1) * 2 + 1)]])],
	 [AC_COMPILE_IFELSE(
	    [AC_LANG_BOOL_COMPILE_TRY(
	       [AC_INCLUDES_DEFAULT],
	       [[($ac_type) (((($ac_type) 1 << ($1 - 2)) - 1) * 2 + 1)
	         < ($ac_type) (((($ac_type) 1 << ($1 - 2)) - 1) * 2 + 2)]])],
	    [],
	    [AS_CASE([$ac_type], [int$1_t],
	       [ac_cv_c_int$1_t=yes],
	       [ac_cv_c_int$1_t=$ac_type])])])
       test "$ac_cv_c_int$1_t" != no && break
     done])
  case $ac_cv_c_int$1_t in #(
  no|yes) ;; #(
  *)
    AC_DEFINE_UNQUOTED([int$1_t], [$ac_cv_c_int$1_t],
      [Define to the type of a signed integer type of width exactly $1 bits
       if such a type exists and the standard includes do not define it.]);;
  esac
])# _AC_TYPE_INT

# _AC_TYPE_UNSIGNED_INT(NBITS)
# ----------------------------
AC_DEFUN([_AC_TYPE_UNSIGNED_INT],
[
  AC_CACHE_CHECK([for uint$1_t], [ac_cv_c_uint$1_t],
    [ac_cv_c_uint$1_t=no
     for ac_type in 'uint$1_t' 'unsigned int' 'unsigned long int' \
	 'unsigned long long int' 'unsigned short int' 'unsigned char'; do
       AC_COMPILE_IFELSE(
	 [AC_LANG_BOOL_COMPILE_TRY(
	    [AC_INCLUDES_DEFAULT],
	    [[($ac_type) -1 >> ($1 - 1) == 1]])],
	 [AS_CASE([$ac_type], [uint$1_t],
	    [ac_cv_c_uint$1_t=yes],
	    [ac_cv_c_uint$1_t=$ac_type])])
       test "$ac_cv_c_uint$1_t" != no && break
     done])
  case $ac_cv_c_uint$1_t in #(
  no|yes) ;; #(
  *)
    m4_bmatch([$1], [^\(8\|32\|64\)$],
      [AC_DEFINE([_UINT$1_T], 1,
	 [Define for Solaris 2.5.1 so the uint$1_t typedef from
	  <sys/synch.h>, <pthread.h>, or <semaphore.h> is not used.
	  If the typedef was allowed, the #define below would cause a
	  syntax error.])])
    AC_DEFINE_UNQUOTED([uint$1_t], [$ac_cv_c_uint$1_t],
      [Define to the type of an unsigned integer type of width exactly $1 bits
       if such a type exists and the standard includes do not define it.]);;
  esac
])# _AC_TYPE_UNSIGNED_INT

# AS_CASE(WORD, [PATTERN1], [IF-MATCHED1]...[DEFAULT])
# ----------------------------------------------------
# Expand into
# | case WORD in
# | PATTERN1) IF-MATCHED1 ;;
# | ...
# | *) DEFAULT ;;
# | esac
m4_define([_AS_CASE],
[m4_if([$#], 0, [m4_fatal([$0: too few arguments: $#])],
       [$#], 1, [  *) $1 ;;],
       [$#], 2, [  $1) m4_default([$2], [:]) ;;],
       [  $1) m4_default([$2], [:]) ;;
$0(m4_shiftn(2, $@))])dnl
])
m4_defun([AS_CASE],
[m4_ifval([$2$3],
[case $1 in
_AS_CASE(m4_shift($@))
esac
])dnl
])# AS_CASE

# _AC_PROG_CC_C99 ([ACTION-IF-AVAILABLE], [ACTION-IF-UNAVAILABLE])
# ----------------------------------------------------------------
# If the C compiler is not in ISO C99 mode by default, try to add an
# option to output variable CC to make it so.  This macro tries
# various options that select ISO C99 on some system or another.  It
# considers the compiler to be in ISO C99 mode if it handles _Bool,
# // comments, flexible array members, inline, long long int, mixed
# code and declarations, named initialization of structs, restrict,
# va_copy, varargs macros, variable declarations in for loops and
# variable length arrays.
AC_DEFUN([_AC_PROG_CC_C99],
[_AC_C_STD_TRY([c99],
[[#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>

// Check varargs macros.  These examples are taken from C99 6.10.3.5.
#define debug(...) fprintf (stderr, __VA_ARGS__)
#define showlist(...) puts (#__VA_ARGS__)
#define report(test,...) ((test) ? puts (#test) : printf (__VA_ARGS__))
static void
test_varargs_macros (void)
{
  int x = 1234;
  int y = 5678;
  debug ("Flag");
  debug ("X = %d\n", x);
  showlist (The first, second, and third items.);
  report (x>y, "x is %d but y is %d", x, y);
}

// Check long long types.
#define BIG64 18446744073709551615ull
#define BIG32 4294967295ul
#define BIG_OK (BIG64 / BIG32 == 4294967297ull && BIG64 % BIG32 == 0)
#if !BIG_OK
  your preprocessor is broken;
#endif
#if BIG_OK
#else
  your preprocessor is broken;
#endif
static long long int bignum = -9223372036854775807LL;
static unsigned long long int ubignum = BIG64;

struct incomplete_array
{
  int datasize;
  double data[];
};

struct named_init {
  int number;
  const wchar_t *name;
  double average;
};

typedef const char *ccp;

static inline int
test_restrict (ccp restrict text)
{
  // See if C++-style comments work.
  // Iterate through items via the restricted pointer.
  // Also check for declarations in for loops.
  for (unsigned int i = 0; *(text+i) != '\0'; ++i)
    continue;
  return 0;
}

// Check varargs and va_copy.
static void
test_varargs (const char *format, ...)
{
  va_list args;
  va_start (args, format);
  va_list args_copy;
  va_copy (args_copy, args);

  const char *str;
  int number;
  float fnumber;

  while (*format)
    {
      switch (*format++)
        {
        case 's': // string
          str = va_arg (args_copy, const char *);
          break;
        case 'd': // int
          number = va_arg (args_copy, int);
          break;
        case 'f': // float
          fnumber = va_arg (args_copy, double);
          break;
        default:
          break;
        }
    }
  va_end (args_copy);
  va_end (args);
}
]],
[[
  // Check bool.
  _Bool success = false;

  // Check restrict.
 if (test_restrict ("String literal") == 0)
    success = true;
  char *restrict newvar = "Another string";

  // Check varargs.
  test_varargs ("s, d' f .", "string", 65, 34.234);
  test_varargs_macros ();

  // Check flexible array members.
  struct incomplete_array *ia =
    malloc (sizeof (struct incomplete_array) + (sizeof (double) * 10));
  ia->datasize = 10;
  for (int i = 0; i < ia->datasize; ++i)
    ia->data[i] = i * 1.234;

  // Check named initializers.
  struct named_init ni = {
    .number = 34,
    .name = L"Test wide string",
    .average = 543.34343,
  };

  ni.number = 58;

  int dynamic_array[ni.number];
  dynamic_array[ni.number - 1] = 543;

  // work around unused variable warnings
  return (!success || bignum == 0LL || ubignum == 0uLL || newvar[0] == 'x'
          || dynamic_array[ni.number - 1] != 543);
]],
dnl Try
dnl GCC         -std=gnu99 (unused restrictive modes: -std=c99 -std=iso9899:1999)
dnl AIX         -qlanglvl=extc99 (unused restrictive mode: -qlanglvl=stdc99)
dnl HP cc       -AC99
dnl Intel ICC   -std=c99, -c99 (deprecated)
dnl IRIX        -c99
dnl Solaris     -xc99=all (Forte Developer 7 C mishandles -xc99 on Solaris 9,
dnl             as it incorrectly assumes C99 semantics for library functions)
dnl Tru64       -c99
dnl with extended modes being tried first.
[[-std=gnu99 -std=c99 -c99 -AC99 -xc99=all -qlanglvl=extc99]], [$1], [$2])[]dnl
])# _AC_PROG_CC_C99


# AC_PROG_CC_C89
# --------------
AC_DEFUN([AC_PROG_CC_C89],
[ AC_REQUIRE([AC_PROG_CC])dnl
  _AC_PROG_CC_C89
])

# AC_PROG_CC_C99
# --------------
AC_DEFUN([AC_PROG_CC_C99],
[ AC_REQUIRE([AC_PROG_CC])dnl
  _AC_PROG_CC_C99
])


# AC_PROG_CC_STDC
# ---------------
AC_DEFUN([AC_PROG_CC_STDC],
[ AC_REQUIRE([AC_PROG_CC])dnl
  AS_CASE([$ac_cv_prog_cc_stdc],
    [no], [ac_cv_prog_cc_c99=no; ac_cv_prog_cc_c89=no],
          [_AC_PROG_CC_C99([ac_cv_prog_cc_stdc=$ac_cv_prog_cc_c99],
             [_AC_PROG_CC_C89([ac_cv_prog_cc_stdc=$ac_cv_prog_cc_c89],
                              [ac_cv_prog_cc_stdc=no])])])dnl
  AC_MSG_CHECKING([for $CC option to accept ISO Standard C])
  AC_CACHE_VAL([ac_cv_prog_cc_stdc], [])
  AS_CASE([$ac_cv_prog_cc_stdc],
    [no], [AC_MSG_RESULT([unsupported])],
    [''], [AC_MSG_RESULT([none needed])],
          [AC_MSG_RESULT([$ac_cv_prog_cc_stdc])])
])

# _AC_C_STD_TRY(STANDARD, TEST-PROLOGUE, TEST-BODY, OPTION-LIST,
#               ACTION-IF-AVAILABLE, ACTION-IF-UNAVAILABLE)
# --------------------------------------------------------------
# Check whether the C compiler accepts features of STANDARD (e.g `c89', `c99')
# by trying to compile a program of TEST-PROLOGUE and TEST-BODY.  If this fails,
# try again with each compiler option in the space-separated OPTION-LIST; if one
# helps, append it to CC.  If eventually successful, run ACTION-IF-AVAILABLE,
# else ACTION-IF-UNAVAILABLE.
AC_DEFUN([_AC_C_STD_TRY],
[AC_MSG_CHECKING([for $CC option to accept ISO ]m4_translit($1, [c], [C]))
AC_CACHE_VAL(ac_cv_prog_cc_$1,
[ac_cv_prog_cc_$1=no
ac_save_CC=$CC
AC_LANG_CONFTEST([AC_LANG_PROGRAM([$2], [$3])])
for ac_arg in '' $4
do
  CC="$ac_save_CC $ac_arg"
  _AC_COMPILE_IFELSE([], [ac_cv_prog_cc_$1=$ac_arg])
  test "x$ac_cv_prog_cc_$1" != "xno" && break
done
rm -f conftest.$ac_ext
CC=$ac_save_CC
])# AC_CACHE_VAL
case "x$ac_cv_prog_cc_$1" in
  x)
    AC_MSG_RESULT([none needed]) ;;
  xno)
    AC_MSG_RESULT([unsupported]) ;;
  *)
    CC="$CC $ac_cv_prog_cc_$1"
    AC_MSG_RESULT([$ac_cv_prog_cc_$1]) ;;
esac
AS_IF([test "x$ac_cv_prog_cc_$1" != xno], [$5], [$6])
])# _AC_C_STD_TRY


