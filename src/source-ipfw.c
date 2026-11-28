/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Nick Rogness <nick@rogness.net>
 * \author Eric Leblond <eric@regit.org>
 *
 * IPFW packet acquisition support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "source-ipfw.h"
#include "util-debug.h"
#include "conf.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-datalink.h"
#include "util-device-private.h"
#include "runmodes.h"

#ifndef IPFW
/* Handle the case if --enable-ipfw was not used
 *
 */

TmEcode NoIPFWSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveIPFWRegister (void)
{

    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_RECEIVEIPFW].Func = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVEIPFW].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictIPFWRegister (void)
{
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_VERDICTIPFW].Func = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTIPFW].flags = TM_FLAG_VERDICT_TM;
}

void TmModuleDecodeIPFWRegister (void)
{
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = NoIPFWSupportExit;
    tmm_modules[TMM_DECODEIPFW].Func = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODEIPFW].cap_flags = 0;
    tmm_modules[TMM_DECODEIPFW].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoIPFWSupportExit(ThreadVars *tv, const void *initdata, void **data)
{

    SCLogError("Error creating thread %s: you do not have support for ipfw "
               "enabled please recompile with --enable-ipfw",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* We have IPFW compiled in */

#include "action-globals.h"
#include "util-misc.h"

#ifdef OS_FREEBSD
#include <sys/sysctl.h>
#endif

#define IPFW_ACCEPT 0
#define IPFW_DROP   1

#define IPFW_SOCKET_POLL_MSEC 300

/* ipfw.buffer-size limits. 64 KiB is about FreeBSD's default of 65636 bytes;
 * a smaller value is most likely a size without a unit. For the upper limit
 * see IPFWMbufLimitOverflows(). */
#define IPFW_BUFFER_SIZE_MIN  (64 * 1024)
#define IPFW_BUFFER_SIZE_MAX  (64 * 1024 * 1024)

extern uint32_t max_pending_packets;

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct IPFWThreadVars_
{
    /* data link type for the thread, probably not needed */
    int datalink;

    /* this one should be not changing after init */
    uint16_t port_num;
    /* position into the NFQ queue var array */
    uint16_t ipfw_index;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
} IPFWThreadVars;

static IPFWThreadVars ipfw_t[IPFW_MAX_QUEUE];
static IPFWQueueVars ipfw_q[IPFW_MAX_QUEUE];
static uint16_t receive_port_num = 0;
static SCMutex ipfw_init_lock;
/* ipfw.buffer-size in bytes, 0 for the kernel default; set by IPFWInitConfig() */
static int ipfw_buffer_size = 0;

/* IPFW Prototypes */
static void *IPFWGetQueue(int number);
static TmEcode ReceiveIPFWThreadInit(ThreadVars *, const void *, void **);
static TmEcode ReceiveIPFWLoop(ThreadVars *tv, void *data, void *slot);
static void ReceiveIPFWThreadExitStats(ThreadVars *, void *);
static TmEcode ReceiveIPFWThreadDeinit(ThreadVars *, void *);

static TmEcode IPFWSetVerdict(ThreadVars *, IPFWThreadVars *, Packet *);
static TmEcode VerdictIPFW(ThreadVars *, Packet *, void *);
static TmEcode VerdictIPFWThreadInit(ThreadVars *, const void *, void **);
static void VerdictIPFWThreadExitStats(ThreadVars *, void *);
static TmEcode VerdictIPFWThreadDeinit(ThreadVars *, void *);

static TmEcode DecodeIPFWThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeIPFWThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeIPFW(ThreadVars *, Packet *, void *);

#ifdef UNITTESTS
static void SourceIPFWRegisterTests(void);
#endif

/**
 * \brief Registration Function for RecieveIPFW.
 */
void TmModuleReceiveIPFWRegister (void)
{
    SCMutexInit(&ipfw_init_lock, NULL);

    tmm_modules[TMM_RECEIVEIPFW].name = "ReceiveIPFW";
    tmm_modules[TMM_RECEIVEIPFW].ThreadInit = ReceiveIPFWThreadInit;
    tmm_modules[TMM_RECEIVEIPFW].Func = NULL;
    tmm_modules[TMM_RECEIVEIPFW].PktAcqLoop = ReceiveIPFWLoop;
    tmm_modules[TMM_RECEIVEIPFW].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEIPFW].ThreadExitPrintStats = ReceiveIPFWThreadExitStats;
    tmm_modules[TMM_RECEIVEIPFW].ThreadDeinit = ReceiveIPFWThreadDeinit;
    tmm_modules[TMM_RECEIVEIPFW].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
                                             SC_CAP_NET_BIND_SERVICE |
                                             SC_CAP_NET_BROADCAST; /** \todo untested */
    tmm_modules[TMM_RECEIVEIPFW].flags = TM_FLAG_RECEIVE_TM;
#ifdef UNITTESTS
    tmm_modules[TMM_RECEIVEIPFW].RegisterTests = SourceIPFWRegisterTests;
#endif
}

/**
 * \brief Registration Function for VerdictIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleVerdictIPFWRegister (void)
{
    tmm_modules[TMM_VERDICTIPFW].name = "VerdictIPFW";
    tmm_modules[TMM_VERDICTIPFW].ThreadInit = VerdictIPFWThreadInit;
    tmm_modules[TMM_VERDICTIPFW].Func = VerdictIPFW;
    tmm_modules[TMM_VERDICTIPFW].ThreadExitPrintStats = VerdictIPFWThreadExitStats;
    tmm_modules[TMM_VERDICTIPFW].ThreadDeinit = VerdictIPFWThreadDeinit;
    tmm_modules[TMM_VERDICTIPFW].cap_flags = SC_CAP_NET_ADMIN | SC_CAP_NET_RAW |
                                             SC_CAP_NET_BIND_SERVICE; /** \todo untested */
    tmm_modules[TMM_VERDICTIPFW].flags = TM_FLAG_VERDICT_TM;
}

/**
 * \brief Registration Function for DecodeIPFW.
 * \todo Unit tests are needed for this module.
 */
void TmModuleDecodeIPFWRegister (void)
{
    tmm_modules[TMM_DECODEIPFW].name = "DecodeIPFW";
    tmm_modules[TMM_DECODEIPFW].ThreadInit = DecodeIPFWThreadInit;
    tmm_modules[TMM_DECODEIPFW].Func = DecodeIPFW;
    tmm_modules[TMM_DECODEIPFW].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEIPFW].ThreadDeinit = DecodeIPFWThreadDeinit;
    tmm_modules[TMM_DECODEIPFW].flags = TM_FLAG_DECODE_TM;
}

static inline void IPFWMutexInit(IPFWQueueVars *nq)
{
    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("workers", active_runmode)) {
        nq->use_mutex = 0;
        SCLogInfo("IPFW running in 'workers' runmode, will not use mutex.");
    } else {
        nq->use_mutex = 1;
    }
    if (nq->use_mutex)
        SCMutexInit(&nq->socket_lock, NULL);
}

static inline void IPFWMutexLock(IPFWQueueVars *nq)
{
    if (nq->use_mutex)
        SCMutexLock(&nq->socket_lock);
}

static inline void IPFWMutexUnlock(IPFWQueueVars *nq)
{
    if (nq->use_mutex)
        SCMutexUnlock(&nq->socket_lock);
}

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

TmEcode ReceiveIPFWLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    IPFWQueueVars *nq = NULL;
    uint8_t pkt[IP_MAXPACKET];
    int pktlen=0;
    struct pollfd IPFWpoll;
    struct timeval IPFWts;
    Packet *p = NULL;

    nq = IPFWGetQueue(ptv->ipfw_index);
    if (nq == NULL) {
        SCLogWarning("Can't get thread variable");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Thread '%s' will run on port %d (item %d)",
              tv->name, nq->port_num, ptv->ipfw_index);

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

    while (1) {
        if (unlikely(suricata_ctl_flags != 0)) {
            SCReturnInt(TM_ECODE_OK);
        }

        IPFWpoll.fd = nq->fd;
        IPFWpoll.events = POLLRDNORM;
        /* Poll the socket for status */
        if ( (poll(&IPFWpoll, 1, IPFW_SOCKET_POLL_MSEC)) > 0) {
            if (!(IPFWpoll.revents & (POLLRDNORM | POLLERR)))
                continue;
        }

        if ((pktlen = recvfrom(nq->fd, pkt, sizeof(pkt), 0,
                               (struct sockaddr *)&nq->ipfw_sin,
                               &nq->ipfw_sinlen)) == -1) {
            /* We received an error on socket read */
            if (errno == EINTR || errno == EWOULDBLOCK) {
                /* Nothing for us to process */
                continue;
            } else {
                SCLogWarning("Read from IPFW divert socket failed: %s", strerror(errno));
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
        /* We have a packet to process */
        memset (&IPFWts, 0, sizeof(struct timeval));
        gettimeofday(&IPFWts, NULL);

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        p = PacketGetFromQueueOrAlloc();
        if (p == NULL) {
            SCReturnInt(TM_ECODE_FAILED);
        }
        PKT_SET_SRC(p, PKT_SRC_WIRE);

        SCLogDebug("Received Packet Len: %d", pktlen);

        p->ts = SCTIME_FROM_TIMEVAL(&IPFWts);

        ptv->pkts++;
        ptv->bytes += pktlen;

        p->datalink = ptv->datalink;

        p->ipfw_v.ipfw_index = ptv->ipfw_index;

        PacketCopyData(p, pkt, pktlen);
        SCLogDebug("Packet info: pkt_len: %" PRIu32 " (pkt %02x, pkt_data %02x)",
                   GET_PKT_LEN(p), *pkt, *(GET_PKT_DATA(p)));

        if (TmThreadsSlotProcessPkt(tv, ((TmSlot *) slot)->slot_next, p)
                != TM_ECODE_OK) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        StatsSyncCountersIfSignalled(&tv->stats);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Parse an ipfw.buffer-size value
 *
 * \param str size string, e.g. "4mb"
 * \param size set on success to the size in bytes, or 0 for the kernel default
 *
 * \retval 0 on success
 * \retval -1 if str is not a size, or is neither 0 nor in
 *         IPFW_BUFFER_SIZE_MIN..IPFW_BUFFER_SIZE_MAX
 */
static int IPFWParseBufferSize(const char *str, int *size)
{
    uint32_t value = 0;

    if (ParseSizeStringU32(str, &value) < 0) {
        return -1;
    }
    if (value != 0 && (value < IPFW_BUFFER_SIZE_MIN || value > IPFW_BUFFER_SIZE_MAX)) {
        return -1;
    }
    *size = (int)value;
    return 0;
}

/**
 * \brief Get ipfw.buffer-size from the configuration
 *
 * \retval size receive buffer size in bytes, 0 to keep the kernel default
 */
static int IPFWConfigGetBufferSize(void)
{
    const char *str = NULL;
    int size = 0;

    if (SCConfGetNonNull("ipfw.buffer-size", &str) != 1) {
        return 0;
    }
    if (IPFWParseBufferSize(str, &size) < 0) {
        SCLogWarning("invalid ipfw.buffer-size '%s', must be 0, or from 64kb to 64mb; keeping "
                     "the kernel default",
                str);
        return 0;
    }
    return size;
}

/**
 * \brief Check whether the kernel's mbuf limit for a buffer would overflow
 *
 * The kernel keeps a socket buffer's mbuf limit, its size times
 * kern.ipc.sockbuf_waste_factor, in 32 bits and reads it as an int in
 * sbspace(). Past INT_MAX the socket can drop every packet. The kernel's own
 * min() with kern.ipc.maxsockbuf doesn't protect against this: the product is
 * truncated to u_int first (min() takes u_int in sys/libkern.h), so a product
 * of 4 GiB or more wraps to a small limit, 0 at exactly 4 GiB, whatever
 * kern.ipc.maxsockbuf is. A kern.ipc.maxsockbuf below 2 GiB saves only the
 * range above INT_MAX and below 4 GiB, and Suricata refuses that range too.
 *
 * With the default factor of 8 the product passes INT_MAX from 256 MiB.
 * IPFW_BUFFER_SIZE_MAX, 64 MiB, stays clear of it for factors up to 31.
 *
 * \param size buffer size in bytes
 * \param waste_factor kern.ipc.sockbuf_waste_factor
 *
 * \retval true if size * waste_factor exceeds INT_MAX
 * \retval false otherwise
 */
static bool IPFWMbufLimitOverflows(uint64_t size, uint64_t waste_factor)
{
    return waste_factor > 0 && size > (uint64_t)INT_MAX / waste_factor;
}

/**
 * \brief Set the receive buffer of a divert socket
 *
 * The kernel drops a diverted packet that doesn't fit in the socket's receive
 * buffer, and Suricata never sees it.
 *
 * Errors only log a warning: divert fails closed, so failing the thread would
 * block all diverted traffic. The socket then keeps the kernel default. The
 * two conditions that depend on sysctls alone, not on the socket, are logged
 * for the first listener only.
 *
 * \param nq queue whose socket to set up
 * \param item index of the queue, as in the "will run on port" message
 * \param size requested size in bytes, IPFW_BUFFER_SIZE_MIN..IPFW_BUFFER_SIZE_MAX
 *
 * \retval 0 if the buffer was set
 * \retval -1 if the socket keeps the kernel default
 */
static int IPFWSetRecvBuffer(const IPFWQueueVars *nq, uint16_t item, int size)
{
#ifdef OS_FREEBSD
    /* kern.ipc.maxsockbuf caps the buffer's mbuf memory; the user guide
     * explains why twice the size is the least to ask for */
    const uint64_t advised = 2 * (uint64_t)size;
#endif

    uint64_t waste_factor = 8; /* the kernel's default */
#ifdef OS_FREEBSD
    unsigned long sysctl_factor = 0;
    size_t sysctl_factor_len = sizeof(sysctl_factor);
    if (sysctlbyname("kern.ipc.sockbuf_waste_factor", &sysctl_factor, &sysctl_factor_len, NULL,
                0) == 0) {
        waste_factor = sysctl_factor;
    } else {
        SCLogDebug("can't read kern.ipc.sockbuf_waste_factor: %s; assuming 8", strerror(errno));
    }
#endif
    if (IPFWMbufLimitOverflows((uint64_t)size, waste_factor)) {
        if (item == 0) {
            SCLogWarning("IPFW divert: kern.ipc.sockbuf_waste_factor %" PRIu64
                         " would overflow the kernel's mbuf limit for a receive buffer of %d "
                         "bytes; lower ipfw.buffer-size or the waste factor; keeping the kernel "
                         "default",
                    waste_factor, size);
        }
        return -1;
    }

    if (setsockopt(nq->fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) {
        int err = errno;
#ifdef OS_FREEBSD
        /* the size is above 8/9 of kern.ipc.maxsockbuf, or over the sbsize limit */
        if (err == ENOBUFS) {
            SCLogWarning("IPFW divert port %" PRIu16 " (item %" PRIu16 "): failed to set receive "
                         "buffer to %d: %s; set kern.ipc.maxsockbuf to at least %" PRIu64
                         " or raise the sbsize resource limit; keeping the kernel default",
                    nq->port_num, item, size, strerror(err), advised);
            return -1;
        }
#endif
        SCLogWarning("IPFW divert port %" PRIu16 " (item %" PRIu16 "): failed to set receive "
                     "buffer to %d: %s; keeping the kernel default",
                nq->port_num, item, size, strerror(err));
        return -1;
    }

    int cur = 0;
    socklen_t len = sizeof(cur);
    if (getsockopt(nq->fd, SOL_SOCKET, SO_RCVBUF, &cur, &len) == 0) {
        SCLogPerf("IPFW divert port %" PRIu16 " (item %" PRIu16 "): receive buffer is %d bytes",
                nq->port_num, item, cur);
    }

#ifdef OS_FREEBSD
    unsigned long maxsockbuf = 0;
    size_t maxsockbuf_len = sizeof(maxsockbuf);
    if (item == 0 &&
            sysctlbyname("kern.ipc.maxsockbuf", &maxsockbuf, &maxsockbuf_len, NULL, 0) == 0 &&
            (uint64_t)maxsockbuf < advised) {
        SCLogWarning("IPFW divert: kern.ipc.maxsockbuf %" PRIu64
                     " caps a receive buffer's mbuf memory, so it may fill before %d bytes; set "
                     "kern.ipc.maxsockbuf to at least %" PRIu64 " and restart",
                (uint64_t)maxsockbuf, size, advised);
    }
#endif
    return 0;
}

/**
 * \brief Init function for RecieveIPFW.
 *
 * This is a setup function for receiving packets
 * via ipfw divert, binds a socket, and prepares to
 * to read from it.
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer to the divert port passed from the user
 * \param data pointer gets populated with IPFWThreadVars
 *
 */
TmEcode ReceiveIPFWThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    struct timeval timev;
    IPFWThreadVars *ntv = (IPFWThreadVars *) initdata;
    IPFWQueueVars *nq = IPFWGetQueue(ntv->ipfw_index);

    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);

    SCEnter();

    IPFWMutexInit(nq);
    /* We need a divert socket to play with */
#ifdef PF_DIVERT
    if ((nq->fd = socket(PF_DIVERT, SOCK_RAW, 0)) == -1) {
#else
    if ((nq->fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT)) == -1) {
#endif
        SCLogError("Can't create divert socket: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    timev.tv_sec = 1;
    timev.tv_usec = 0;

    if (setsockopt(nq->fd, SOL_SOCKET, SO_RCVTIMEO, &timev, sizeof(timev)) == -1) {
        SCLogError("Can't set IPFW divert socket timeout: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    /* before bind(), so no packet is queued against the default buffer */
    if (ipfw_buffer_size > 0) {
        (void)IPFWSetRecvBuffer(nq, ntv->ipfw_index, ipfw_buffer_size);
    }

    nq->ipfw_sinlen=sizeof(nq->ipfw_sin);
    memset(&nq->ipfw_sin, 0, nq->ipfw_sinlen);
    nq->ipfw_sin.sin_family = PF_INET;
    nq->ipfw_sin.sin_addr.s_addr = INADDR_ANY;
    nq->ipfw_sin.sin_port = htons(nq->port_num);

    /* Bind that SOB */
    if (bind(nq->fd, (struct sockaddr *)&nq->ipfw_sin, nq->ipfw_sinlen) == -1) {
        SCLogError("Can't bind divert socket on port %d: %s", nq->port_num, strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    ntv->datalink = DLT_RAW;
    DatalinkSetGlobalType(DLT_RAW);

    *data = (void *)ntv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats to the screen at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void ReceiveIPFWThreadExitStats(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;

    SCEnter();

    SCLogNotice("(%s) Treated: Pkts %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
            tv->name, ptv->pkts, ptv->bytes, ptv->errs);
    SCLogNotice("(%s) Verdict: Accepted %"PRIu32", Dropped %"PRIu32 "",
            tv->name, ptv->accepted, ptv->dropped);


    SCReturn;
}

/**
 * \brief DeInit function closes divert socket at exit.
 * \todo Unit tests are needed for this module.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode ReceiveIPFWThreadDeinit(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    IPFWQueueVars *nq = IPFWGetQueue(ptv->ipfw_index);

    SCEnter();

    if (close(nq->fd) < 0) {
        SCLogWarning("Unable to disable ipfw socket: %s", strerror(errno));
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 * \todo Unit tests are needed for this module.
 *
 * DecodeIPFW decodes packets from IPFW and passes
 * them off to the proper link type decoder.
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode DecodeIPFW(ThreadVars *tv, Packet *p, void *data)
{
    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    SCEnter();

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    /* Process IP packets */
    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("DecodeIPFW ip4 processing");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        if (unlikely(GET_PKT_LEN(p) > USHRT_MAX)) {
            return TM_ECODE_FAILED;
        }
        SCLogDebug("DecodeIPFW ip6 processing");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    } else {
        /* We don't support anything besides IP packets for now, bridged packets? */
        SCLogInfo("IPFW unknown protocol support %02x", *GET_PKT_DATA(p));
       SCReturnInt(TM_ECODE_FAILED);
    }

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function initializes the DecodeThreadVariables
 *
 *
 * \param tv pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode DecodeIPFWThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodeIPFWThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function sets the Verdict and processes the packet
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 */
TmEcode IPFWSetVerdict(ThreadVars *tv, IPFWThreadVars *ptv, Packet *p)
{
    uint32_t verdict;
#if 0
    struct pollfd IPFWpoll;
#endif
    IPFWQueueVars *nq = NULL;

    SCEnter();

    if (p == NULL) {
        SCLogWarning("Packet is NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    nq = IPFWGetQueue(p->ipfw_v.ipfw_index);
    if (nq == NULL) {
        SCLogWarning("No thread found");
        SCReturnInt(TM_ECODE_FAILED);
    }

#if 0
    IPFWpoll.fd = nq->fd;
    IPFWpoll.events = POLLWRNORM;
#endif

    if (PacketCheckAction(p, ACTION_DROP)) {
        verdict = IPFW_DROP;
    } else {
        verdict = IPFW_ACCEPT;
    }

    if (verdict == IPFW_ACCEPT) {
        SCLogDebug("IPFW Verdict is to Accept");
        ptv->accepted++;

        /* For divert sockets, accepting means writing the
         * packet back to the socket for ipfw to pick up
         */
        SCLogDebug("IPFWSetVerdict writing to socket %d, %p, %u", nq->fd, GET_PKT_DATA(p),GET_PKT_LEN(p));

#if 0
        while ((poll(&IPFWpoll,1,IPFW_SOCKET_POLL_MSEC)) < 1) {
            /* Did we receive a signal to shutdown */
            if (TmThreadsCheckFlag(tv, THV_KILL) || TmThreadsCheckFlag(tv, THV_PAUSE)) {
                SCLogInfo("Received ThreadShutdown: IPFW divert socket writing interrupted");
                SCReturnInt(TM_ECODE_OK);
            }
        }
#endif

        IPFWMutexLock(nq);
        if (sendto(nq->fd, GET_PKT_DATA(p), GET_PKT_LEN(p), 0,(struct sockaddr *)&nq->ipfw_sin, nq->ipfw_sinlen) == -1) {
            int r = errno;
            switch (r) {
                default:
                    SCLogWarning("Write to ipfw divert socket failed: %s", strerror(r));
                    IPFWMutexUnlock(nq);
                    SCReturnInt(TM_ECODE_FAILED);
                case EHOSTDOWN:
                case ENETDOWN:
                    break;
            }
        }

        IPFWMutexUnlock(nq);

        SCLogDebug("Sent Packet back into IPFW Len: %d",GET_PKT_LEN(p));

    } /* end IPFW_ACCEPT */


    if (verdict == IPFW_DROP) {
        SCLogDebug("IPFW SetVerdict is to DROP");
        ptv->dropped++;

        /** \todo For divert sockets, dropping means not writing the packet back to the socket.
         * Need to see if there is some better way to free the packet from the queue */

    } /* end IPFW_DROP */

    SCReturnInt(TM_ECODE_OK);
}


/**
 * \brief This function handles the Verdict processing
 * \todo Unit tests are needed for this module.
 *
 *
 * \param tv pointer to ThreadVars
 * \param p pointer to the Packet
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFW(ThreadVars *tv, Packet *p, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    TmEcode retval = TM_ECODE_OK;

    SCEnter();

    /* can't verdict a "fake" packet */
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* This came from NFQ.
     * If this is a tunnel packet we check if we are ready to verdict already. */
    if (PacketIsTunnel(p)) {
        bool verdict = VerdictTunnelPacket(p);

        /* don't verdict if we are not ready */
        if (verdict) {
            SCLogDebug("Setting verdict on tunnel");
            retval = IPFWSetVerdict(tv, ptv, p->root ? p->root : p);
        }
    } else {
        /* no tunnel, verdict normally */
        SCLogDebug("Setting verdict on non-tunnel");
        retval = IPFWSetVerdict(tv, ptv, p);
    }

    SCReturnInt(retval);
}

/**
 * \brief This function initializes the VerdictThread
 *
 *
 * \param t pointer to ThreadVars
 * \param initdata pointer for passing in args
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadInit(ThreadVars *tv, const void *initdata, void **data)
{

    IPFWThreadVars *ptv = NULL;

    SCEnter();

    /* Setup Thread vars */
    if ((ptv = SCCalloc(1, sizeof(IPFWThreadVars))) == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function deinitializes the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
TmEcode VerdictIPFWThreadDeinit(ThreadVars *tv, void *data)
{

    SCEnter();

    /* We don't need to do anything...not sure quite yet */


    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function prints stats for the VerdictThread
 *
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into IPFWThreadVars for ptv
 */
void VerdictIPFWThreadExitStats(ThreadVars *tv, void *data)
{
    IPFWThreadVars *ptv = (IPFWThreadVars *)data;
    SCLogInfo("IPFW Processing: - (%s) Pkts accepted %" PRIu32 ", dropped %" PRIu32 "", tv->name, ptv->accepted, ptv->dropped);
}

/**
 *  \brief Add an IPFW divert
 *
 *  \param string with the queue name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int IPFWRegisterQueue(char *queue)
{
    IPFWThreadVars *ntv = NULL;
    IPFWQueueVars *nq = NULL;
    /* Extract the queue number from the specified command line argument */
    uint16_t port_num = 0;
    if ((StringParseUint16(&port_num, 10, strlen(queue), queue)) < 0)
    {
        SCLogError("specified queue number %s is not "
                   "valid",
                queue);
        return -1;
    }

    SCMutexLock(&ipfw_init_lock);
    if (receive_port_num >= IPFW_MAX_QUEUE) {
        SCLogError("too much IPFW divert port registered (%d)", receive_port_num);
        SCMutexUnlock(&ipfw_init_lock);
        return -1;
    }
    if (receive_port_num == 0) {
        memset(&ipfw_t, 0, sizeof(ipfw_t));
        memset(&ipfw_q, 0, sizeof(ipfw_q));
    }

    ntv = &ipfw_t[receive_port_num];
    ntv->ipfw_index = receive_port_num;

    nq = &ipfw_q[receive_port_num];
    nq->port_num = port_num;
    receive_port_num++;
    SCMutexUnlock(&ipfw_init_lock);
    LiveRegisterDeviceName(queue);

    SCLogDebug("Queue \"%s\" registered.", queue);
    return 0;
}

/**
 *  \brief Read the ipfw settings from the configuration
 *
 *  IPFWRegisterQueue() runs while the command line is parsed, before
 *  suricata.yaml is loaded, so the ipfw section is read here instead. The
 *  runmodes call it before they start the receive threads. Reading it once
 *  also reports an invalid value once, not once per divert port.
 */
void IPFWInitConfig(void)
{
    ipfw_buffer_size = IPFWConfigGetBufferSize();
}

/**
 *  \brief Get a pointer to the IPFW queue at index
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the IPFWThreadVars at index
 *  \retval NULL on error
 */
void *IPFWGetQueue(int number)
{
    if (number >= receive_port_num)
        return NULL;

    return (void *)&ipfw_q[number];
}

/**
 *  \brief Get a pointer to the IPFW thread at index
 *
 *  This function is temporary used as configuration parser.
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the IPFWThreadVars at index
 *  \retval NULL on error
 */
void *IPFWGetThread(int number)
{
    if (number >= receive_port_num)
        return NULL;

    return (void *)&ipfw_t[number];
}

#ifdef UNITTESTS
#include "conf-yaml-loader.h"

static int IPFWParseBufferSizeTest01(void)
{
    int size = -1;

    FAIL_IF(IPFWParseBufferSize("0", &size) != 0);
    FAIL_IF(size != 0);
    FAIL_IF(IPFWParseBufferSize("0kb", &size) != 0);
    FAIL_IF(size != 0);
    FAIL_IF(IPFWParseBufferSize("64kb", &size) != 0);
    FAIL_IF(size != IPFW_BUFFER_SIZE_MIN);
    FAIL_IF(IPFWParseBufferSize("65636", &size) != 0);
    FAIL_IF(size != 65636);
    FAIL_IF(IPFWParseBufferSize("1MiB", &size) != 0);
    FAIL_IF(size != 1024 * 1024);
    FAIL_IF(IPFWParseBufferSize("1.5mb", &size) != 0);
    FAIL_IF(size != 1536 * 1024);
    FAIL_IF(IPFWParseBufferSize("4mb", &size) != 0);
    FAIL_IF(size != 4 * 1024 * 1024);
    FAIL_IF(IPFWParseBufferSize("64mb", &size) != 0);
    FAIL_IF(size != IPFW_BUFFER_SIZE_MAX);

    PASS;
}

static int IPFWParseBufferSizeTest02(void)
{
    int size = 1234;

    /* not a size */
    FAIL_IF(IPFWParseBufferSize("", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("abc", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("-1", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("4tb", &size) != -1);
    /* below the minimum, e.g. a forgotten unit */
    FAIL_IF(IPFWParseBufferSize("1", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("65535", &size) != -1);
    /* above the maximum */
    FAIL_IF(IPFWParseBufferSize("67108865", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("512mb", &size) != -1);
    FAIL_IF(IPFWParseBufferSize("4gb", &size) != -1);
    /* size is only written on success */
    FAIL_IF(size != 1234);

    PASS;
}

/**
 * \brief Load a YAML string into a fresh configuration and get the size
 *
 * \retval size what IPFWConfigGetBufferSize() returned, -2 if the YAML didn't load
 */
static int IPFWBufferSizeFromYaml(const char *conf)
{
    int size = -2;

    SCConfCreateContextBackup();
    SCConfInit();
    if (SCConfYamlLoadString(conf, strlen(conf)) == 0) {
        size = IPFWConfigGetBufferSize();
    }
    SCConfDeInit();
    SCConfRestoreContextBackup();
    return size;
}

static int IPFWConfigGetBufferSizeTest01(void)
{
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: 2mb\n") !=
            2 * 1024 * 1024);
    /* a dotted key, as in a file included from suricata.yaml */
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw.buffer-size: 4mb\n") != 4 * 1024 * 1024);

    PASS;
}

static int IPFWConfigGetBufferSizeTest02(void)
{
    /* unset, empty, invalid, out of range and 0 all keep the kernel default */
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nother: 1\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size:\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: lots\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: 1\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: 128mb\n") != 0);
    FAIL_IF(IPFWBufferSizeFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: 0\n") != 0);

    PASS;
}

static int IPFWMbufLimitOverflowsTest01(void)
{
    /* the default factor and the largest accepted size */
    FAIL_IF(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MAX, 8));
    FAIL_IF(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MAX, 31));
    /* 64 MiB * 32 = 2^31, one past INT_MAX */
    FAIL_IF_NOT(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MAX, 32));
    FAIL_IF_NOT(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MIN, 32768));
    FAIL_IF(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MIN, 32767));
    /* huge factors must not wrap the multiplication */
    FAIL_IF_NOT(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MIN, UINT64_MAX));
    /* a factor of 0 is no arithmetic overflow, although the kernel then gives
     * every socket an mbuf limit of 0; that is not this check's business */
    FAIL_IF(IPFWMbufLimitOverflows(IPFW_BUFFER_SIZE_MAX, 0));

    PASS;
}

/**
 * \brief Load a YAML string into a fresh configuration and run IPFWInitConfig()
 *
 * \retval size the size IPFWInitConfig() stored, -2 if the YAML didn't load
 */
static int IPFWInitConfigFromYaml(const char *conf)
{
    const int saved = ipfw_buffer_size;
    int size = -2;

    SCConfCreateContextBackup();
    SCConfInit();
    if (SCConfYamlLoadString(conf, strlen(conf)) == 0) {
        IPFWInitConfig();
        size = ipfw_buffer_size;
    }
    SCConfDeInit();
    SCConfRestoreContextBackup();
    ipfw_buffer_size = saved;
    return size;
}

static int IPFWInitConfigTest01(void)
{
    /* the configured size reaches what ReceiveIPFWThreadInit() uses */
    FAIL_IF(IPFWInitConfigFromYaml("%YAML 1.1\n---\nipfw:\n  buffer-size: 2mb\n") !=
            2 * 1024 * 1024);
    /* and a configuration without it means the kernel default */
    FAIL_IF(IPFWInitConfigFromYaml("%YAML 1.1\n---\nother: 1\n") != 0);

    PASS;
}

/**
 * \brief Whether a failed socket() means this host has no IPv4 socket to test on
 *
 * \param err errno of the failed socket() call
 */
static bool IPFWTestNoSocket(int err)
{
    return err == EAFNOSUPPORT || err == EPROTONOSUPPORT || err == EPERM || err == EACCES;
}

static int IPFWSetRecvBufferTest01(void)
{
    /* a plain UDP socket stands in for the divert socket */
    IPFWQueueVars nq;
    memset(&nq, 0, sizeof(nq));
    nq.port_num = 8000;
    nq.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nq.fd == -1) {
        int err = errno;
        if (!IPFWTestNoSocket(err)) {
            SCLogWarning("can't create an AF_INET socket: %s", strerror(err));
            FAIL;
        }
        SCLogInfo("can't create an AF_INET socket: %s; nothing to test", strerror(err));
        PASS;
    }

    int before = 0;
    socklen_t len = sizeof(before);
    int rc_before = getsockopt(nq.fd, SOL_SOCKET, SO_RCVBUF, &before, &len);
    /* a size the socket doesn't have already */
    const int size = (before == 128 * 1024) ? 256 * 1024 : 128 * 1024;
    int set = IPFWSetRecvBuffer(&nq, 0, size);

    int cur = 0;
    len = sizeof(cur);
    int rc = getsockopt(nq.fd, SOL_SOCKET, SO_RCVBUF, &cur, &len);
    close(nq.fd);
    FAIL_IF(rc_before != 0 || rc != 0);
    FAIL_IF(set != 0);
    FAIL_IF(cur == before);
    /* a kernel may round the size up */
    FAIL_IF(cur < size);
#ifdef OS_FREEBSD
    /* FreeBSD reports the size as it was set */
    FAIL_IF(cur != size);
#endif

    PASS;
}

#ifdef OS_FREEBSD
static int IPFWSetRecvBufferTest02(void)
{
    /* the kernel refuses a size above 8/9 of kern.ipc.maxsockbuf with ENOBUFS;
     * that is logged, and the socket keeps its default buffer */
    unsigned long maxsockbuf = 0;
    size_t maxsockbuf_len = sizeof(maxsockbuf);
    FAIL_IF(sysctlbyname("kern.ipc.maxsockbuf", &maxsockbuf, &maxsockbuf_len, NULL, 0) != 0);
    if (maxsockbuf > IPFW_BUFFER_SIZE_MAX) {
        /* no size in the option's range is refused on this host */
        SCLogInfo("kern.ipc.maxsockbuf %lu is above %d: nothing to test", maxsockbuf,
                IPFW_BUFFER_SIZE_MAX);
        PASS;
    }

    IPFWQueueVars nq;
    memset(&nq, 0, sizeof(nq));
    nq.port_num = 8000;
    nq.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (nq.fd == -1) {
        int err = errno;
        if (!IPFWTestNoSocket(err)) {
            SCLogWarning("can't create an AF_INET socket: %s", strerror(err));
            FAIL;
        }
        SCLogInfo("can't create an AF_INET socket: %s; nothing to test", strerror(err));
        PASS;
    }

    int before = 0;
    socklen_t len = sizeof(before);
    int rc_before = getsockopt(nq.fd, SOL_SOCKET, SO_RCVBUF, &before, &len);
    int set = IPFWSetRecvBuffer(&nq, 0, (int)maxsockbuf);
    int after = 0;
    len = sizeof(after);
    int rc_after = getsockopt(nq.fd, SOL_SOCKET, SO_RCVBUF, &after, &len);
    close(nq.fd);
    FAIL_IF(set != -1);
    FAIL_IF(rc_before != 0 || rc_after != 0);
    FAIL_IF(before <= 0);
    FAIL_IF(after != before);

    PASS;
}
#endif /* OS_FREEBSD */

static void SourceIPFWRegisterTests(void)
{
    UtRegisterTest("IPFWParseBufferSizeTest01", IPFWParseBufferSizeTest01);
    UtRegisterTest("IPFWParseBufferSizeTest02", IPFWParseBufferSizeTest02);
    UtRegisterTest("IPFWConfigGetBufferSizeTest01", IPFWConfigGetBufferSizeTest01);
    UtRegisterTest("IPFWConfigGetBufferSizeTest02", IPFWConfigGetBufferSizeTest02);
    UtRegisterTest("IPFWMbufLimitOverflowsTest01", IPFWMbufLimitOverflowsTest01);
    UtRegisterTest("IPFWInitConfigTest01", IPFWInitConfigTest01);
    UtRegisterTest("IPFWSetRecvBufferTest01", IPFWSetRecvBufferTest01);
#ifdef OS_FREEBSD
    UtRegisterTest("IPFWSetRecvBufferTest02", IPFWSetRecvBufferTest02);
#endif
}
#endif /* UNITTESTS */

#endif /* End ifdef IPFW */

/* eof */

