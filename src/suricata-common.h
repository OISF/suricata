/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include <config.h>
#endif

#ifndef CLS
#warning "L1 cache line size not detected during build. Assuming 64 bytes."
#define CLS 64
#endif

#if HAVE_STDIO_H
#include <stdio.h>
#endif

#if HAVE_STDINT_h
#include <stdint.h>
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

#include <pcre.h>

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

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
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

#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif

#ifdef HAVE_PCAP_PCAP_H
#include <pcap/pcap.h>
#endif

#ifdef HAVE_PCAP_BPF_H
#include <pcap/bpf.h>
#endif

#if __CYGWIN__
#if !defined _X86_ && !defined __x86_64
#define _X86_
#endif
#endif

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

#if !__CYGWIN__
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif /* !__CYGWIN__ */

#if CPPCHECK==1
#define BUG_ON(x) if (((x))) exit(1)
#else
#ifdef HAVE_ASSERT_H
#include <assert.h>
#define BUG_ON(x) assert(!(x))
#else
#define BUG_ON(x)
#endif
#endif

/* we need this to stringify the defines which are supplied at compiletime see:
   http://gcc.gnu.org/onlinedocs/gcc-3.4.1/cpp/Stringification.html#Stringification */
#define xstr(s) str(s)
#define str(s) #s

/** type for the internal signature id. Since it's used in the matching engine
 *  extensively keeping this as small as possible reduces the overall memory
 *  footprint of the engine. Set to uint32_t if the engine needs to support
 *  more than 64k sigs. */
//#define SigIntId uint16_t
#define SigIntId uint32_t

/** same for pattern id's */
#define PatIntId uint16_t

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
	#if defined(__X86__) || defined(_X86_)
		#define __WORDSIZE 32
	#else
		#if defined(__X86_64__) || defined(_X86_64_)
			#define __WORDSIZE 64
		#endif
	#endif

    #ifndef __WORDSIZE
        #warning Defaulting to __WORDSIZE 32
        #define __WORDSIZE 32
    #endif
#endif

/** darwin doesn't defined __BYTE_ORDER and friends, but BYTE_ORDER */
#ifndef __BYTE_ORDER
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif

#ifndef __LITTLE_ENDIAN
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif

#ifndef __BIG_ENDIAN
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif

#ifndef HAVE_PCRE_FREE_STUDY
#define pcre_free_study pcre_free
#endif

#ifndef MIN
#define MIN(x, y) (((x)<(y))?(x):(y))
#endif

typedef enum PacketProfileDetectId_ {
    PROF_DETECT_MPM,
    PROF_DETECT_MPM_PACKET,         /* PKT MPM */
    PROF_DETECT_MPM_PKT_STREAM,     /* PKT inspected with stream MPM */
    PROF_DETECT_MPM_STREAM,         /* STREAM MPM */
    PROF_DETECT_MPM_URI,
    PROF_DETECT_MPM_HCBD,
    PROF_DETECT_MPM_HSBD,
    PROF_DETECT_MPM_HHD,
    PROF_DETECT_MPM_HRHD,
    PROF_DETECT_MPM_HMD,
    PROF_DETECT_MPM_HCD,
    PROF_DETECT_MPM_HRUD,
    PROF_DETECT_MPM_HSMD,
    PROF_DETECT_MPM_HSCD,
    PROF_DETECT_MPM_HUAD,
    PROF_DETECT_MPM_HHHD,
    PROF_DETECT_MPM_HRHHD,
    PROF_DETECT_MPM_DNSQUERY,
    PROF_DETECT_IPONLY,
    PROF_DETECT_RULES,
    PROF_DETECT_STATEFUL,
    PROF_DETECT_PREFILTER,
    PROF_DETECT_NONMPMLIST,
    PROF_DETECT_ALERT,
    PROF_DETECT_CLEANUP,
    PROF_DETECT_GETSGH,
    PROF_DETECT_MPM_FD_SMTP,

    PROF_DETECT_SIZE,
} PacketProfileDetectId;

#include <htp/htp.h>
#include "threads.h"
#include "tm-threads-common.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-mem.h"
#include "detect-engine-alert.h"
#include "util-optimize.h"
#include "util-path.h"
#include "util-conf.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *src, size_t siz);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

extern int coverage_unittests;
extern int g_ut_modules;
extern int g_ut_covered;
#endif /* __SURICATA_COMMON_H__ */

