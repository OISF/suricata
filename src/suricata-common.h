/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Common includes, etc.
 */

#ifndef __SURICATA_COMMON_H__
#define __SURICATA_COMMON_H__

#ifdef DEBUG
#define DBG_PERF
#endif

#define TRUE   1
#define FALSE  0

#define _GNU_SOURCE
#define __USE_GNU

#if HAVE_CONFIG_H
#include <autoconf.h>
#endif

#ifndef CLS
#warning "L1 cache line size not detected during build. Assuming 64 bytes."
#define CLS 64
#endif

#if HAVE_DIRENT_H
#include <dirent.h>
#endif

#if HAVE_STDIO_H
#include <stdio.h>
#endif

#if HAVE_STDDEF_H
#include <stddef.h>
#endif

#if HAVE_STDINT_h
#include <stdint.h>
#endif

#if HAVE_STDBOOL_H
#include <stdbool.h>
#endif

#if HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if HAVE_LIMITS_H
#include <limits.h>
#endif

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#if HAVE_SYSCALL_H
#include <syscall.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h> /* for gettid(2) */
#endif

#if HAVE_SCHED_H
#include <sched.h>     /* for sched_setaffinity(2) */
#endif

#ifdef HAVE_TYPE_U_LONG_NOT_DEFINED
typedef unsigned long int u_long;
#endif
#ifdef HAVE_TYPE_U_INT_NOT_DEFINED
typedef unsigned int u_int;
#endif
#ifdef HAVE_TYPE_U_SHORT_NOT_DEFINED
typedef unsigned short u_short;
#endif
#ifdef HAVE_TYPE_U_CHAR_NOT_DEFINED
typedef unsigned char u_char;
#endif

#include <pcre2.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#ifdef OS_WIN32
#include "win32-syslog.h"
#endif /* OS_WIN32 */
#endif /* HAVE_SYSLOG_H */

#ifdef OS_WIN32
#include "win32-misc.h"
#include "win32-service.h"
#endif /* OS_WIN32 */

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_POLL_H
#include <poll.h>
#endif

#if HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#if HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#if __CYGWIN__
#if !defined _X86_ && !defined __x86_64
#define _X86_
#endif
#endif

#if !__CYGWIN__
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif /* !__CYGWIN__ */

#ifdef HAVE_WINDOWS_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#endif

#ifdef HAVE_W32API_WINBASE_H
#include <w32api/winbase.h>
#endif

#ifdef HAVE_W32API_WTYPES_H
#include <w32api/wtypes.h>
#endif

#ifndef SC_PCAP_DONT_INCLUDE_PCAP_H
#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif
#endif

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <jansson.h>
#ifndef JSON_ESCAPE_SLASH
#define JSON_ESCAPE_SLASH 0
#endif

#ifdef HAVE_MAGIC
#include <magic.h>
#endif

/* we need this to stringify the defines which are supplied at compiletime see:
   http://gcc.gnu.org/onlinedocs/gcc-3.4.1/cpp/Stringification.html#Stringification */
#define xstr(s) str(s)
#define str(s) #s

#if CPPCHECK==1
    #define BUG_ON(x) if (((x))) exit(1)
#else
    #if defined HAVE_ASSERT_H && !defined NDEBUG
    #include <assert.h>
        #define BUG_ON(x) assert(!(x))
    #else
        #define BUG_ON(x) do {      \
            if (((x))) {            \
                fprintf(stderr, "BUG at %s:%d(%s)\n", __FILE__, __LINE__, __func__);    \
                fprintf(stderr, "Code: '%s'\n", xstr((x)));                             \
                exit(EXIT_FAILURE); \
            }                       \
        } while(0)
    #endif
#endif

/** type for the internal signature id. Since it's used in the matching engine
 *  extensively keeping this as small as possible reduces the overall memory
 *  footprint of the engine. Set to uint32_t if the engine needs to support
 *  more than 64k sigs. */
//#define SigIntId uint16_t
#define SigIntId uint32_t

/** same for pattern id's */
#define PatIntId uint32_t

/** FreeBSD does not define __WORDSIZE, but it uses __LONG_BIT */
#ifndef __WORDSIZE
    #ifdef __LONG_BIT
        #define __WORDSIZE __LONG_BIT
    #else
        #ifdef LONG_BIT
            #define __WORDSIZE LONG_BIT
        #endif
    #endif
#endif

/** Windows does not define __WORDSIZE, but it uses __X86__ */
#ifndef __WORDSIZE
    #if defined(__X86__) || defined(_X86_) || defined(_M_IX86)
        #define __WORDSIZE 32
    #else
        #if defined(__X86_64__) || defined(_X86_64_) || \
            defined(__x86_64)   || defined(__x86_64__) || \
            defined(__amd64)    || defined(__amd64__)
            #define __WORDSIZE 64
        #endif
    #endif
#endif

/** if not succesful yet try the data models */
#ifndef __WORDSIZE
    #if defined(_ILP32) || defined(__ILP32__)
        #define __WORDSIZE 32
    #endif
    #if defined(_LP64) || defined(__LP64__)
        #define __WORDSIZE 64
    #endif
#endif

#ifndef __WORDSIZE
    #warning Defaulting to __WORDSIZE 32
    #define __WORDSIZE 32
#endif

/** darwin doesn't defined __BYTE_ORDER and friends, but BYTE_ORDER */
#ifndef __BYTE_ORDER
    #if defined(BYTE_ORDER)
        #define __BYTE_ORDER BYTE_ORDER
    #elif defined(__BYTE_ORDER__)
        #define __BYTE_ORDER __BYTE_ORDER__
    #else
        #error "byte order not detected"
    #endif
#endif

#ifndef __LITTLE_ENDIAN
    #if defined(LITTLE_ENDIAN)
        #define __LITTLE_ENDIAN LITTLE_ENDIAN
    #elif defined(__ORDER_LITTLE_ENDIAN__)
        #define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
    #endif
#endif

#ifndef __BIG_ENDIAN
    #if defined(BIG_ENDIAN)
        #define __BIG_ENDIAN BIG_ENDIAN
    #elif defined(__ORDER_BIG_ENDIAN__)
        #define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
    #endif
#endif

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
    #error "byte order: can't figure out big or little"
#endif

#ifndef MIN
#define MIN(x, y) (((x)<(y))?(x):(y))
#endif

#ifndef MAX
#define MAX(x, y) (((x)<(y))?(y):(x))
#endif

#define BIT_U8(n)  ((uint8_t)(1 << (n)))
#define BIT_U16(n) ((uint16_t)(1 << (n)))
#define BIT_U32(n) (1UL  << (n))
#define BIT_U64(n) (1ULL << (n))

#define WARN_UNUSED __attribute__((warn_unused_result))

#if defined(__MINGW32__)
#define ATTR_FMT_PRINTF(x, y) __attribute__((format(__MINGW_PRINTF_FORMAT, (x), (y))))
#elif defined(__GNUC__)
#define ATTR_FMT_PRINTF(x, y) __attribute__((format(printf, (x), (y))))
#else
#define ATTR_FMT_PRINTF(x, y)
#endif

#define SCNtohl(x) (uint32_t)ntohl((x))
#define SCNtohs(x) (uint16_t)ntohs((x))

/* swap flags if one of them is set, otherwise do nothing. */
#define SWAP_FLAGS(flags, a, b)                     \
    do {                                            \
        if (((flags) & ((a)|(b))) == (a)) {         \
            (flags) &= ~(a);                        \
            (flags) |= (b);                         \
        } else if (((flags) & ((a)|(b))) == (b)) {  \
            (flags) &= ~(b);                        \
            (flags) |= (a);                         \
        }                                           \
    } while(0)

#define SWAP_VARS(type, a, b)           \
    do {                                \
        type t = (a);                   \
        (a) = (b);                      \
        (b) = t;                        \
    } while (0)

#include <ctype.h>
#define u8_tolower(c) ((uint8_t)tolower((uint8_t)(c)))
#define u8_toupper(c) ((uint8_t)toupper((uint8_t)(c)))

typedef enum PacketProfileDetectId_ {
    PROF_DETECT_SETUP,
    PROF_DETECT_GETSGH,
    PROF_DETECT_IPONLY,
    PROF_DETECT_RULES,
    PROF_DETECT_TX,
    PROF_DETECT_PF_PKT,
    PROF_DETECT_PF_PAYLOAD,
    PROF_DETECT_PF_TX,
    PROF_DETECT_PF_RECORD,
    PROF_DETECT_PF_SORT1,
    PROF_DETECT_PF_SORT2,
    PROF_DETECT_NONMPMLIST,
    PROF_DETECT_ALERT,
    PROF_DETECT_TX_UPDATE,
    PROF_DETECT_CLEANUP,

    PROF_DETECT_SIZE,
} PacketProfileDetectId;

/** \note update PacketProfileLoggertIdToString if you change anything here */
typedef enum {
    LOGGER_UNDEFINED,

    /* TX loggers first for low logger IDs */
    LOGGER_HTTP,
    LOGGER_TLS_STORE,
    LOGGER_TLS,
    LOGGER_JSON_DNS,
    LOGGER_JSON_HTTP,
    LOGGER_JSON_SMTP,
    LOGGER_JSON_TLS,
    LOGGER_JSON_NFS,
    LOGGER_JSON_TFTP,
    LOGGER_JSON_FTP,
    LOGGER_JSON_DNP3_TS,
    LOGGER_JSON_DNP3_TC,
    LOGGER_JSON_SSH,
    LOGGER_JSON_SMB,
    LOGGER_JSON_IKE,
    LOGGER_JSON_KRB5,
    LOGGER_JSON_QUIC,
    LOGGER_JSON_MODBUS,
    LOGGER_JSON_DHCP,
    LOGGER_JSON_SNMP,
    LOGGER_JSON_SIP,
    LOGGER_JSON_TEMPLATE_RUST,
    LOGGER_JSON_RFB,
    LOGGER_JSON_MQTT,
    LOGGER_JSON_PGSQL,
    LOGGER_JSON_TEMPLATE,
    LOGGER_JSON_RDP,
    LOGGER_JSON_DCERPC,
    LOGGER_JSON_HTTP2,

    LOGGER_FILE,
    LOGGER_FILEDATA,

    /** \warning when we exceed what we can express as a u32 flag here we need to update
     *           LoggerFlags::flags (u32) and `tx_logged` in src/output-tx.c */

    /* non-tx loggers below */

    LOGGER_ALERT_DEBUG,
    LOGGER_ALERT_FAST,
    LOGGER_ALERT_SYSLOG,
    LOGGER_JSON_ALERT,
    LOGGER_JSON_ANOMALY,
    LOGGER_JSON_DROP,
    LOGGER_FILE_STORE,
    LOGGER_JSON_FILE,
    LOGGER_TCP_DATA,
    LOGGER_JSON_FLOW,
    LOGGER_JSON_NETFLOW,
    LOGGER_STATS,
    LOGGER_JSON_STATS,
    LOGGER_PCAP,
    LOGGER_JSON_METADATA,
    LOGGER_JSON_FRAME,
    LOGGER_SIZE,
} LoggerId;

#ifndef HAVE_LUA

/* If we don't have Lua, create a typedef for lua_State so the
 * exported Lua functions don't fail the build. */
typedef void lua_State;

#else

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#endif

#include "tm-threads-common.h"
#include "util-optimize.h"
#include "util-mem.h"
#include "util-memcmp.h"
#include "util-atomic.h"
#include "util-unittest.h"

// pseudo system headers
#include "queue.h"
#include "tree.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#ifndef HAVE_STRPTIME
char *strptime(const char * __restrict, const char * __restrict, struct tm * __restrict);
#endif

#ifndef HAVE_FWRITE_UNLOCKED
#define SCFwriteUnlocked    fwrite
#define SCFflushUnlocked    fflush
#define SCClearErrUnlocked  clearerr
#define SCFerrorUnlocked    ferror
#else
#define SCFwriteUnlocked    fwrite_unlocked
#define SCFflushUnlocked    fflush_unlocked
#define SCClearErrUnlocked  clearerr_unlocked
#define SCFerrorUnlocked    ferror_unlocked
#endif
extern int coverage_unittests;
extern int g_ut_modules;
extern int g_ut_covered;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

#endif /* __SURICATA_COMMON_H__ */
