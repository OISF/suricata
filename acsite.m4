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
