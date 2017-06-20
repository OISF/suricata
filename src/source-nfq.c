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
 * \author Victor Julien <victor@inliniac.net>
 * \author Eric Leblond <eric@regit.org>
 *
 *  Netfilter's netfilter_queue support for reading packets from the
 *  kernel and setting verdicts back to it (inline mode).
 *  Supported on Linux and Windows.
 *
 * \todo test if Receive and Verdict if both are present
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-queuehandlers.h"
#include "tmqh-packetpool.h"

#include "conf.h"
#include "config.h"
#include "conf-yaml-loader.h"
#include "source-nfq-prototypes.h"
#include "action-globals.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-byte.h"
#include "util-privs.h"
#include "util-device.h"

#include "runmodes.h"

#include "source-nfq.h"

#ifndef NFQ
/** Handle the case where no NFQ support is compiled in.
 *
 */

TmEcode NoNFQSupportExit(ThreadVars *, const void *, void **);

void TmModuleReceiveNFQRegister (void)
{
    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_RECEIVENFQ].Func = NULL;
    tmm_modules[TMM_RECEIVENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENFQ].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFQ].cap_flags = SC_CAP_NET_ADMIN;
    tmm_modules[TMM_RECEIVENFQ].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictNFQRegister (void)
{
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_VERDICTNFQ].Func = NULL;
    tmm_modules[TMM_VERDICTNFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTNFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_VERDICTNFQ].RegisterTests = NULL;
    tmm_modules[TMM_VERDICTNFQ].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleDecodeNFQRegister (void)
{
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].ThreadInit = NoNFQSupportExit;
    tmm_modules[TMM_DECODENFQ].Func = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENFQ].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFQ].cap_flags = 0;
    tmm_modules[TMM_DECODENFQ].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNFQSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NFQ_NOSUPPORT,"Error creating thread %s: you do not have support for nfqueue "
           "enabled please recompile with --enable-nfqueue", tv->name);
    exit(EXIT_FAILURE);
}

#else /* implied we do have NFQ support */

extern int max_pending_packets;

#define MAX_ALREADY_TREATED 5
#define NFQ_VERDICT_RETRY_TIME 3
static int already_seen_warning;
static int runmode_workers;

#define NFQ_BURST_FACTOR 4

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

//#define NFQ_DFT_QUEUE_LEN NFQ_BURST_FACTOR * MAX_PENDING
//#define NFQ_NF_BUFSIZE 1500 * NFQ_DFT_QUEUE_LEN

typedef struct NFQThreadVars_
{
    uint16_t nfq_index;
    ThreadVars *tv;
    TmSlot *slot;

    char *data; /** Per function and thread data */
    int datalen; /** Length of per function and thread data */

    CaptureStats stats;
} NFQThreadVars;
/* shared vars for all for nfq queues and threads */
static NFQGlobalVars nfq_g;

static NFQThreadVars g_nfq_t[NFQ_MAX_QUEUE];
static NFQQueueVars g_nfq_q[NFQ_MAX_QUEUE];
static uint16_t receive_queue_num = 0;
static SCMutex nfq_init_lock;

TmEcode ReceiveNFQLoop(ThreadVars *tv, void *data, void *slot);
TmEcode ReceiveNFQThreadInit(ThreadVars *, const void *, void **);
TmEcode ReceiveNFQThreadDeinit(ThreadVars *, void *);
void ReceiveNFQThreadExitStats(ThreadVars *, void *);

TmEcode VerdictNFQ(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode VerdictNFQThreadInit(ThreadVars *, const void *, void **);
TmEcode VerdictNFQThreadDeinit(ThreadVars *, void *);

TmEcode DecodeNFQ(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodeNFQThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodeNFQThreadDeinit(ThreadVars *tv, void *data);

TmEcode NFQSetVerdict(Packet *p);

typedef enum NFQMode_ {
    NFQ_ACCEPT_MODE,
    NFQ_REPEAT_MODE,
    NFQ_ROUTE_MODE,
} NFQMode;

#define NFQ_FLAG_FAIL_OPEN  (1 << 0)

typedef struct NFQCnf_ {
    NFQMode mode;
    uint32_t mark;
    uint32_t mask;
    uint32_t bypass_mark;
    uint32_t bypass_mask;
    uint32_t next_queue;
    uint32_t flags;
    uint8_t batchcount;
} NFQCnf;

NFQCnf nfq_config;

void TmModuleReceiveNFQRegister (void)
{
    /* XXX create a general NFQ setup function */
    memset(&nfq_g, 0, sizeof(nfq_g));
    SCMutexInit(&nfq_init_lock, NULL);

    tmm_modules[TMM_RECEIVENFQ].name = "ReceiveNFQ";
    tmm_modules[TMM_RECEIVENFQ].ThreadInit = ReceiveNFQThreadInit;
    tmm_modules[TMM_RECEIVENFQ].Func = NULL;
    tmm_modules[TMM_RECEIVENFQ].PktAcqLoop = ReceiveNFQLoop;
    tmm_modules[TMM_RECEIVENFQ].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENFQ].ThreadExitPrintStats = ReceiveNFQThreadExitStats;
    tmm_modules[TMM_RECEIVENFQ].ThreadDeinit = ReceiveNFQThreadDeinit;
    tmm_modules[TMM_RECEIVENFQ].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVENFQ].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleVerdictNFQRegister (void)
{
    tmm_modules[TMM_VERDICTNFQ].name = "VerdictNFQ";
    tmm_modules[TMM_VERDICTNFQ].ThreadInit = VerdictNFQThreadInit;
    tmm_modules[TMM_VERDICTNFQ].Func = VerdictNFQ;
    tmm_modules[TMM_VERDICTNFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_VERDICTNFQ].ThreadDeinit = VerdictNFQThreadDeinit;
    tmm_modules[TMM_VERDICTNFQ].RegisterTests = NULL;
}

void TmModuleDecodeNFQRegister (void)
{
    tmm_modules[TMM_DECODENFQ].name = "DecodeNFQ";
    tmm_modules[TMM_DECODENFQ].ThreadInit = DecodeNFQThreadInit;
    tmm_modules[TMM_DECODENFQ].Func = DecodeNFQ;
    tmm_modules[TMM_DECODENFQ].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENFQ].ThreadDeinit = DecodeNFQThreadDeinit;
    tmm_modules[TMM_DECODENFQ].RegisterTests = NULL;
    tmm_modules[TMM_DECODENFQ].flags = TM_FLAG_DECODE_TM;
}

/** \brief          To initialize the NFQ global configuration data
 *
 *  \param  quiet   It tells the mode of operation, if it is TRUE nothing will
 *                  be get printed.
 */
void NFQInitConfig(char quiet)
{
    intmax_t value = 0;
    const char *nfq_mode = NULL;
    int boolval;

    SCLogDebug("Initializing NFQ");

    memset(&nfq_config,  0, sizeof(nfq_config));

    if ((ConfGet("nfq.mode", &nfq_mode)) == 0) {
        nfq_config.mode = NFQ_ACCEPT_MODE;
    } else {
        if (!strcmp("accept", nfq_mode)) {
            nfq_config.mode = NFQ_ACCEPT_MODE;
        } else if (!strcmp("repeat", nfq_mode)) {
            nfq_config.mode = NFQ_REPEAT_MODE;
        }  else if (!strcmp("route", nfq_mode)) {
            nfq_config.mode = NFQ_ROUTE_MODE;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Unknown nfq.mode");
            exit(EXIT_FAILURE);
        }
    }

    (void)ConfGetBool("nfq.fail-open", (int *)&boolval);
    if (boolval) {
#ifdef HAVE_NFQ_SET_QUEUE_FLAGS
        SCLogInfo("Enabling fail-open on queue");
        nfq_config.flags |= NFQ_FLAG_FAIL_OPEN;
#else
        SCLogError(SC_ERR_NFQ_NOSUPPORT,
                   "nfq.%s set but NFQ library has no support for it.", "fail-open");
#endif
    }

    if ((ConfGetInt("nfq.repeat-mark", &value)) == 1) {
        nfq_config.mark = (uint32_t)value;
    }

    if ((ConfGetInt("nfq.repeat-mask", &value)) == 1) {
        nfq_config.mask = (uint32_t)value;
    }

    if ((ConfGetInt("nfq.bypass-mark", &value)) == 1) {
        nfq_config.bypass_mark = (uint32_t)value;
    }

    if ((ConfGetInt("nfq.bypass-mask", &value)) == 1) {
        nfq_config.bypass_mask = (uint32_t)value;
    }

    if ((ConfGetInt("nfq.route-queue", &value)) == 1) {
        nfq_config.next_queue = ((uint32_t)value) << 16;
    }

    if ((ConfGetInt("nfq.batchcount", &value)) == 1) {
#ifdef HAVE_NFQ_SET_VERDICT_BATCH
        if (value > 255) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "nfq.batchcount cannot exceed 255.");
            value = 255;
        }
        if (value > 1)
            nfq_config.batchcount = (uint8_t) (value - 1);
#else
        SCLogWarning(SC_ERR_NFQ_NOSUPPORT,
                   "nfq.%s set but NFQ library has no support for it.", "batchcount");
#endif
    }

    if (!quiet) {
        switch (nfq_config.mode) {
            case NFQ_ACCEPT_MODE:
                SCLogInfo("NFQ running in standard ACCEPT/DROP mode");
                break;
            case NFQ_REPEAT_MODE:
                SCLogInfo("NFQ running in REPEAT mode with mark %"PRIu32"/%"PRIu32,
                        nfq_config.mark, nfq_config.mask);
                break;
            case NFQ_ROUTE_MODE:
                SCLogInfo("NFQ running in route mode with next queue %"PRIu32,
                        nfq_config.next_queue >> 16);
            break;
        }
    }

}

static uint8_t NFQVerdictCacheLen(NFQQueueVars *t)
{
#ifdef HAVE_NFQ_SET_VERDICT_BATCH
    return t->verdict_cache.len;
#else
    return 0;
#endif
}

static void NFQVerdictCacheFlush(NFQQueueVars *t)
{
#ifdef HAVE_NFQ_SET_VERDICT_BATCH
    int ret;
    int iter = 0;

    do {
        if (t->verdict_cache.mark_valid)
            ret = nfq_set_verdict_batch2(t->qh,
                                         t->verdict_cache.packet_id,
                                         t->verdict_cache.verdict,
                                         t->verdict_cache.mark);
        else
            ret = nfq_set_verdict_batch(t->qh,
                                        t->verdict_cache.packet_id,
                                        t->verdict_cache.verdict);
    } while ((ret < 0) && (iter++ < NFQ_VERDICT_RETRY_TIME));

    if (ret < 0) {
        SCLogWarning(SC_ERR_NFQ_SET_VERDICT, "nfq_set_verdict_batch failed: %s",
                     strerror(errno));
    } else {
        t->verdict_cache.len = 0;
        t->verdict_cache.mark_valid = 0;
    }
#endif
}

static int NFQVerdictCacheAdd(NFQQueueVars *t, Packet *p, uint32_t verdict)
{
#ifdef HAVE_NFQ_SET_VERDICT_BATCH
    if (t->verdict_cache.maxlen == 0)
        return -1;

    if (p->flags & PKT_STREAM_MODIFIED || verdict == NF_DROP)
        goto flush;

    if (p->flags & PKT_MARK_MODIFIED) {
        if (!t->verdict_cache.mark_valid) {
            if (t->verdict_cache.len)
                goto flush;
            t->verdict_cache.mark_valid = 1;
            t->verdict_cache.mark = p->nfq_v.mark;
        } else if (t->verdict_cache.mark != p->nfq_v.mark) {
            goto flush;
        }
    } else if (t->verdict_cache.mark_valid) {
        goto flush;
    }

    if (t->verdict_cache.len == 0) {
        t->verdict_cache.verdict = verdict;
    } else if (t->verdict_cache.verdict != verdict)
        goto flush;

    /* same verdict, mark not set or identical -> can cache */
    t->verdict_cache.packet_id = p->nfq_v.id;

    if (t->verdict_cache.len >= t->verdict_cache.maxlen)
        NFQVerdictCacheFlush(t);
    else
        t->verdict_cache.len++;
    return 0;
 flush:
    /* can't cache. Flush current cache and signal caller it should send single verdict */
    if (NFQVerdictCacheLen(t) > 0)
        NFQVerdictCacheFlush(t);
#endif
    return -1;
}

static inline void NFQMutexInit(NFQQueueVars *nq)
{
    char *active_runmode = RunmodeGetActive();

    if (active_runmode && !strcmp("workers", active_runmode)) {
        nq->use_mutex = 0;
        runmode_workers = 1;
        SCLogInfo("NFQ running in 'workers' runmode, will not use mutex.");
    } else {
        nq->use_mutex = 1;
        runmode_workers = 0;
        SCMutexInit(&nq->mutex_qh, NULL);
    }
}

#define NFQMutexLock(nq) do {           \
    if ((nq)->use_mutex)                \
        SCMutexLock(&(nq)->mutex_qh);   \
} while (0)

#define NFQMutexUnlock(nq) do {         \
    if ((nq)->use_mutex)                \
        SCMutexUnlock(&(nq)->mutex_qh); \
} while (0)

/**
 * \brief Read data from nfq message and setup Packet
 *
 * \note
 * In case of error, this function verdict the packet
 * to avoid skb to get stuck in kernel.
 */
static int NFQSetupPkt (Packet *p, struct nfq_q_handle *qh, void *data)
{
    struct nfq_data *tb = (struct nfq_data *)data;
    int ret;
    char *pktdata;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph != NULL) {
        p->nfq_v.id = ntohl(ph->packet_id);
        //p->nfq_v.hw_protocol = ntohs(p->nfq_v.ph->hw_protocol);
        p->nfq_v.hw_protocol = ph->hw_protocol;
    }
    /* coverity[missing_lock] */
    p->nfq_v.mark = nfq_get_nfmark(tb);
    if (nfq_config.mode == NFQ_REPEAT_MODE) {
        if ((nfq_config.mark & nfq_config.mask) ==
                (p->nfq_v.mark & nfq_config.mask)) {
            int iter = 0;
            if (already_seen_warning < MAX_ALREADY_TREATED)
                SCLogInfo("Packet seems already treated by suricata");
            already_seen_warning++;
            do {
                ret = nfq_set_verdict(qh, p->nfq_v.id, NF_ACCEPT, 0, NULL);
            } while ((ret < 0) && (iter++ < NFQ_VERDICT_RETRY_TIME));
            if (ret < 0) {
                SCLogWarning(SC_ERR_NFQ_SET_VERDICT,
                             "nfq_set_verdict of %p failed %" PRId32 ": %s",
                             p, ret, strerror(errno));
            }
            return -1 ;
        }
    }
    p->nfq_v.ifi  = nfq_get_indev(tb);
    p->nfq_v.ifo  = nfq_get_outdev(tb);
    p->nfq_v.verdicted = 0;

#ifdef NFQ_GET_PAYLOAD_SIGNED
    ret = nfq_get_payload(tb, &pktdata);
#else
    ret = nfq_get_payload(tb, (unsigned char **) &pktdata);
#endif /* NFQ_GET_PAYLOAD_SIGNED */
    if (ret > 0) {
        /* nfq_get_payload returns a pointer to a part of memory
         * that is not preserved over the lifetime of our packet.
         * So we need to copy it. */
        if (ret > 65536) {
            /* Will not be able to copy data ! Set length to 0
             * to trigger an error in packet decoding.
             * This is unlikely to happen */
            SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "NFQ sent too big packet");
            SET_PKT_LEN(p, 0);
        } else if (runmode_workers) {
            PacketSetData(p, (uint8_t *)pktdata, ret);
        } else {
            PacketCopyData(p, (uint8_t *)pktdata, ret);
        }
    } else if (ret ==  -1) {
        /* unable to get pointer to data, ensure packet length is zero.
         * This will trigger an error in packet decoding */
        SET_PKT_LEN(p, 0);
    }

    ret = nfq_get_timestamp(tb, &p->ts);
    if (ret != 0 || p->ts.tv_sec == 0) {
        memset (&p->ts, 0, sizeof(struct timeval));
        gettimeofday(&p->ts, NULL);
    }

    p->datalink = DLT_RAW;
    return 0;
}

static void NFQReleasePacket(Packet *p)
{
    if (unlikely(!p->nfq_v.verdicted)) {
        PACKET_UPDATE_ACTION(p, ACTION_DROP);
        NFQSetVerdict(p);
    }
    PacketFreeOrRelease(p);
}

/**
 * \brief bypass callback function for NFQ
 *
 * \param p a Packet to use information from to trigger bypass
 * \return 1 if bypass is successful, 0 if not
 */
static int NFQBypassCallback(Packet *p)
{
    if (IS_TUNNEL_PKT(p)) {
        /* real tunnels may have multiple flows inside them, so bypass can't
         * work for those. Rebuilt packets from IP fragments are fine. */
        if (p->flags & PKT_REBUILT_FRAGMENT) {
            Packet *tp = p->root ? p->root : p;
            SCMutexLock(&tp->tunnel_mutex);
            tp->nfq_v.mark = (nfq_config.bypass_mark & nfq_config.bypass_mask)
                | (tp->nfq_v.mark & ~nfq_config.bypass_mask);
            tp->flags |= PKT_MARK_MODIFIED;
            SCMutexUnlock(&tp->tunnel_mutex);
            return 1;
        }
        return 0;
    } else {
        /* coverity[missing_lock] */
        p->nfq_v.mark = (nfq_config.bypass_mark & nfq_config.bypass_mask)
                        | (p->nfq_v.mark & ~nfq_config.bypass_mask);
        p->flags |= PKT_MARK_MODIFIED;
    }

    return 1;
}

static int NFQCallBack(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                       struct nfq_data *nfa, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    ThreadVars *tv = ntv->tv;
    int ret;

    /* grab a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        return -1;
    }
    PKT_SET_SRC(p, PKT_SRC_WIRE);

    p->nfq_v.nfq_index = ntv->nfq_index;
    /* if bypass mask is set then we may want to bypass so set pointer */
    if (nfq_config.bypass_mask) {
        p->BypassPacketsFlow = NFQBypassCallback;
    }
    ret = NFQSetupPkt(p, qh, (void *)nfa);
    if (ret == -1) {
#ifdef COUNTERS
        NFQQueueVars *q = NFQGetQueue(ntv->nfq_index);
        q->errs++;
        q->pkts++;
        q->bytes += GET_PKT_LEN(p);
#endif /* COUNTERS */
        /* NFQSetupPkt is issuing a verdict
           so we only recycle Packet and leave */
        TmqhOutputPacketpool(tv, p);
        return 0;
    }

    p->ReleasePacket = NFQReleasePacket;

#ifdef COUNTERS
    NFQQueueVars *q = NFQGetQueue(ntv->nfq_index);
    q->pkts++;
    q->bytes += GET_PKT_LEN(p);
#endif /* COUNTERS */

    if (ntv->slot) {
        if (TmThreadsSlotProcessPkt(tv, ntv->slot, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(ntv->tv, p);
            return -1;
        }
    } else {
        /* pass on... */
        tv->tmqh_out(tv, p);
    }

    return 0;
}

static TmEcode NFQInitThread(NFQThreadVars *t, uint32_t queue_maxlen)
{
    struct timeval tv;
    int opt;
    NFQQueueVars *q = NFQGetQueue(t->nfq_index);
    if (q == NULL) {
        SCLogError(SC_ERR_NFQ_OPEN, "no queue for given index");
        return TM_ECODE_FAILED;
    }
    SCLogDebug("opening library handle");
    q->h = nfq_open();
    if (q->h == NULL) {
        SCLogError(SC_ERR_NFQ_OPEN, "nfq_open() failed");
        return TM_ECODE_FAILED;
    }

    if (nfq_g.unbind == 0)
    {
        /* VJ: on my Ubuntu Hardy system this fails the first time it's
         * run. Ignoring the error seems to have no bad effects. */
        SCLogDebug("unbinding existing nf_queue handler for AF_INET (if any)");
        if (nfq_unbind_pf(q->h, AF_INET) < 0) {
            SCLogError(SC_ERR_NFQ_UNBIND, "nfq_unbind_pf() for AF_INET failed");
            exit(EXIT_FAILURE);
        }
        if (nfq_unbind_pf(q->h, AF_INET6) < 0) {
            SCLogError(SC_ERR_NFQ_UNBIND, "nfq_unbind_pf() for AF_INET6 failed");
            exit(EXIT_FAILURE);
        }
        nfq_g.unbind = 1;

        SCLogDebug("binding nfnetlink_queue as nf_queue handler for AF_INET and AF_INET6");

        if (nfq_bind_pf(q->h, AF_INET) < 0) {
            SCLogError(SC_ERR_NFQ_BIND, "nfq_bind_pf() for AF_INET failed");
            exit(EXIT_FAILURE);
        }
        if (nfq_bind_pf(q->h, AF_INET6) < 0) {
            SCLogError(SC_ERR_NFQ_BIND, "nfq_bind_pf() for AF_INET6 failed");
            exit(EXIT_FAILURE);
        }
    }

    SCLogInfo("binding this thread %d to queue '%" PRIu32 "'", t->nfq_index, q->queue_num);

    /* pass the thread memory as a void ptr so the
     * callback function has access to it. */
    q->qh = nfq_create_queue(q->h, q->queue_num, &NFQCallBack, (void *)t);
    if (q->qh == NULL) {
        SCLogError(SC_ERR_NFQ_CREATE_QUEUE, "nfq_create_queue failed");
        return TM_ECODE_FAILED;
    }

    SCLogDebug("setting copy_packet mode");

    /* 05DC = 1500 */
    //if (nfq_set_mode(nfq_t->qh, NFQNL_COPY_PACKET, 0x05DC) < 0) {
    if (nfq_set_mode(q->qh, NFQNL_COPY_PACKET, 0xFFFF) < 0) {
        SCLogError(SC_ERR_NFQ_SET_MODE, "can't set packet_copy mode");
        return TM_ECODE_FAILED;
    }

#ifdef HAVE_NFQ_MAXLEN
    if (queue_maxlen > 0) {
        SCLogInfo("setting queue length to %" PRId32 "", queue_maxlen);

        /* non-fatal if it fails */
        if (nfq_set_queue_maxlen(q->qh, queue_maxlen) < 0) {
            SCLogWarning(SC_ERR_NFQ_MAXLEN, "can't set queue maxlen: your kernel probably "
                    "doesn't support setting the queue length");
        }
    }
#endif /* HAVE_NFQ_MAXLEN */

    /* set netlink buffer size to a decent value */
    nfnl_rcvbufsiz(nfq_nfnlh(q->h), queue_maxlen * 1500);
    SCLogInfo("setting nfnl bufsize to %" PRId32 "", queue_maxlen * 1500);

    q->nh = nfq_nfnlh(q->h);
    q->fd = nfnl_fd(q->nh);
    NFQMutexInit(q);

    /* Set some netlink specific option on the socket to increase
	performance */
    opt = 1;
#ifdef NETLINK_BROADCAST_SEND_ERROR
    if (setsockopt(q->fd, SOL_NETLINK,
                   NETLINK_BROADCAST_SEND_ERROR, &opt, sizeof(int)) == -1) {
        SCLogWarning(SC_ERR_NFQ_SETSOCKOPT,
                     "can't set netlink broadcast error: %s",
                     strerror(errno));
    }
#endif
    /* Don't send error about no buffer space available but drop the
	packets instead */
#ifdef NETLINK_NO_ENOBUFS
    if (setsockopt(q->fd, SOL_NETLINK,
                   NETLINK_NO_ENOBUFS, &opt, sizeof(int)) == -1) {
        SCLogWarning(SC_ERR_NFQ_SETSOCKOPT,
                     "can't set netlink enobufs: %s",
                     strerror(errno));
    }
#endif

#ifdef HAVE_NFQ_SET_QUEUE_FLAGS
    if (nfq_config.flags & NFQ_FLAG_FAIL_OPEN) {
        uint32_t flags = NFQA_CFG_F_FAIL_OPEN;
        uint32_t mask = NFQA_CFG_F_FAIL_OPEN;
        int r = nfq_set_queue_flags(q->qh, mask, flags);

        if (r == -1) {
            SCLogWarning(SC_ERR_NFQ_SET_MODE, "can't set fail-open mode: %s",
                         strerror(errno));
        } else {
            SCLogInfo("fail-open mode should be set on queue");
        }
    }
#endif

#ifdef HAVE_NFQ_SET_VERDICT_BATCH
    if (runmode_workers) {
        q->verdict_cache.maxlen = nfq_config.batchcount;
    } else if (nfq_config.batchcount) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "nfq.batchcount is only valid in workers runmode.");
    }
#endif

    /* set a timeout to the socket so we can check for a signal
     * in case we don't get packets for a longer period. */
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if(setsockopt(q->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
        SCLogWarning(SC_ERR_NFQ_SETSOCKOPT, "can't set socket timeout: %s", strerror(errno));
    }

    SCLogDebug("nfq_q->h %p, nfq_q->nh %p, nfq_q->qh %p, nfq_q->fd %" PRId32 "",
            q->h, q->nh, q->qh, q->fd);

    return TM_ECODE_OK;
}

TmEcode ReceiveNFQThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCMutexLock(&nfq_init_lock);

    sigset_t sigs;
    sigfillset(&sigs);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    NFQThreadVars *ntv = (NFQThreadVars *) initdata;
    /* store the ThreadVars pointer in our NFQ thread context
     * as we will need it in our callback function */
    ntv->tv = tv;

    int r = NFQInitThread(ntv, (max_pending_packets * NFQ_BURST_FACTOR));
    if (r != TM_ECODE_OK) {
        SCLogError(SC_ERR_NFQ_THREAD_INIT, "nfq thread failed to initialize");

        SCMutexUnlock(&nfq_init_lock);
        exit(EXIT_FAILURE);
    }

#define T_DATA_SIZE 70000
    ntv->data = SCMalloc(T_DATA_SIZE);
    if (ntv->data == NULL) {
        SCMutexUnlock(&nfq_init_lock);
        return TM_ECODE_FAILED;
    }
    ntv->datalen = T_DATA_SIZE;
#undef T_DATA_SIZE

    *data = (void *)ntv;

    SCMutexUnlock(&nfq_init_lock);
    return TM_ECODE_OK;
}


TmEcode ReceiveNFQThreadDeinit(ThreadVars *t, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    NFQQueueVars *nq = NFQGetQueue(ntv->nfq_index);

    if (ntv->data != NULL) {
        SCFree(ntv->data);
        ntv->data = NULL;
    }
    ntv->datalen = 0;

    NFQMutexLock(nq);
    SCLogDebug("starting... will close queuenum %" PRIu32 "", nq->queue_num);
    if (nq->qh) {
        nfq_destroy_queue(nq->qh);
        nq->qh = NULL;
    }
    NFQMutexUnlock(nq);

    return TM_ECODE_OK;
}


TmEcode VerdictNFQThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    NFQThreadVars *ntv = (NFQThreadVars *) initdata;

    CaptureStatsSetup(tv, &ntv->stats);

    *data = (void *)ntv;
    return TM_ECODE_OK;
}

TmEcode VerdictNFQThreadDeinit(ThreadVars *tv, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    NFQQueueVars *nq = NFQGetQueue(ntv->nfq_index);

    SCLogDebug("starting... will close queuenum %" PRIu32 "", nq->queue_num);
    NFQMutexLock(nq);
    if (nq->qh) {
        nfq_destroy_queue(nq->qh);
        nq->qh = NULL;
    }
    NFQMutexUnlock(nq);

    return TM_ECODE_OK;
}

/**
 *  \brief Add a Netfilter queue
 *
 *  \param string with the queue name
 *
 *  \retval 0 on success.
 *  \retval -1 on failure.
 */
int NFQRegisterQueue(char *queue)
{
    NFQThreadVars *ntv = NULL;
    NFQQueueVars *nq = NULL;
    /* Extract the queue number from the specified command line argument */
    uint16_t queue_num = 0;
    if ((ByteExtractStringUint16(&queue_num, 10, strlen(queue), queue)) < 0)
    {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified queue number %s is not "
                                        "valid", queue);
        return -1;
    }

    SCMutexLock(&nfq_init_lock);
    if (receive_queue_num >= NFQ_MAX_QUEUE) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "too much Netfilter queue registered (%d)",
                   receive_queue_num);
        SCMutexUnlock(&nfq_init_lock);
        return -1;
    }
    if (receive_queue_num == 0) {
        memset(&g_nfq_t, 0, sizeof(g_nfq_t));
        memset(&g_nfq_q, 0, sizeof(g_nfq_q));
    }

    ntv = &g_nfq_t[receive_queue_num];
    ntv->nfq_index = receive_queue_num;

    nq = &g_nfq_q[receive_queue_num];
    nq->queue_num = queue_num;
    receive_queue_num++;
    SCMutexUnlock(&nfq_init_lock);
    LiveRegisterDevice(queue);

    SCLogDebug("Queue \"%s\" registered.", queue);
    return 0;
}



/**
 *  \brief Get a pointer to the NFQ queue at index
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the NFQThreadVars at index
 *  \retval NULL on error
 */
void *NFQGetQueue(int number)
{
    if (number >= receive_queue_num)
        return NULL;

    return (void *)&g_nfq_q[number];
}

/**
 *  \brief Get a pointer to the NFQ thread at index
 *
 *  This function is temporary used as configuration parser.
 *
 *  \param number idx of the queue in our array
 *
 *  \retval ptr pointer to the NFQThreadVars at index
 *  \retval NULL on error
 */
void *NFQGetThread(int number)
{
    if (number >= receive_queue_num)
        return NULL;

    return (void *)&g_nfq_t[number];
}

/**
 * \brief NFQ function to get a packet from the kernel
 *
 * \note separate functions for Linux and Win32 for readability.
 */
static void NFQRecvPkt(NFQQueueVars *t, NFQThreadVars *tv)
{
    int rv, ret;
    int flag = NFQVerdictCacheLen(t) ? MSG_DONTWAIT : 0;

    /* XXX what happens on rv == 0? */
    rv = recv(t->fd, tv->data, tv->datalen, flag);

    if (rv < 0) {
        if (errno == EINTR || errno == EWOULDBLOCK) {
            /* no error on timeout */
            if (flag)
                NFQVerdictCacheFlush(t);
        } else {
#ifdef COUNTERS
            NFQMutexLock(t);
            t->errs++;
            NFQMutexUnlock(t);
#endif /* COUNTERS */
        }
    } else if(rv == 0) {
        SCLogWarning(SC_ERR_NFQ_RECV, "recv got returncode 0");
    } else {
#ifdef DBG_PERF
        if (rv > t->dbg_maxreadsize)
            t->dbg_maxreadsize = rv;
#endif /* DBG_PERF */

        //printf("NFQRecvPkt: t %p, rv = %" PRId32 "\n", t, rv);

        NFQMutexLock(t);
        if (t->qh != NULL) {
            ret = nfq_handle_packet(t->h, tv->data, rv);
        } else {
            SCLogWarning(SC_ERR_NFQ_HANDLE_PKT, "NFQ handle has been destroyed");
            ret = -1;
        }
        NFQMutexUnlock(t);

        if (ret != 0) {
            SCLogWarning(SC_ERR_NFQ_HANDLE_PKT, "nfq_handle_packet error %"PRId32" %s",
                    ret, strerror(errno));
        }
    }
}

/**
 *  \brief Main NFQ reading Loop function
 */
TmEcode ReceiveNFQLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    NFQQueueVars *nq = NFQGetQueue(ntv->nfq_index);

    ntv->slot = ((TmSlot *) slot)->slot_next;

    while(1) {
        if (suricata_ctl_flags != 0) {
            NFQMutexLock(nq);
            if (nq->qh) {
                nfq_destroy_queue(nq->qh);
                nq->qh = NULL;
            }
            NFQMutexUnlock(nq);
            break;
        }
        NFQRecvPkt(nq, ntv);

        StatsSyncCountersIfSignalled(tv);
    }
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief NFQ receive module stats printing function
 */
void ReceiveNFQThreadExitStats(ThreadVars *tv, void *data)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    NFQQueueVars *nq = NFQGetQueue(ntv->nfq_index);
#ifdef COUNTERS
    SCLogNotice("(%s) Treated: Pkts %" PRIu32 ", Bytes %" PRIu64 ", Errors %" PRIu32 "",
            tv->name, nq->pkts, nq->bytes, nq->errs);
    SCLogNotice("(%s) Verdict: Accepted %"PRIu32", Dropped %"PRIu32", Replaced %"PRIu32,
            tv->name, nq->accepted, nq->dropped, nq->replaced);
#endif
}

/**
 * \brief NFQ verdict function
 */
TmEcode NFQSetVerdict(Packet *p)
{
    int iter = 0;
    int ret = 0;
    uint32_t verdict = NF_ACCEPT;
    /* we could also have a direct pointer but we need to have a ref counf in this case */
    NFQQueueVars *t = g_nfq_q + p->nfq_v.nfq_index;

    /** \todo add a test on validity of the entry NFQQueueVars could have been
     *  wipeout
     */

    p->nfq_v.verdicted = 1;

    /* can't verdict a "fake" packet */
    if (PKT_IS_PSEUDOPKT(p)) {
        return TM_ECODE_OK;
    }

    //printf("%p verdicting on queue %" PRIu32 "\n", t, t->queue_num);
    NFQMutexLock(t);

    if (t->qh == NULL) {
        /* Somebody has started a clean-up, we leave */
        NFQMutexUnlock(t);
        return TM_ECODE_OK;
    }

    if (PACKET_TEST_ACTION(p, ACTION_DROP)) {
        verdict = NF_DROP;
#ifdef COUNTERS
        t->dropped++;
#endif /* COUNTERS */
    } else {
        switch (nfq_config.mode) {
            default:
            case NFQ_ACCEPT_MODE:
                verdict = NF_ACCEPT;
                break;
            case NFQ_REPEAT_MODE:
                verdict = NF_REPEAT;
                break;
            case NFQ_ROUTE_MODE:
                verdict = ((uint32_t) NF_QUEUE) | nfq_config.next_queue;
                break;
        }

        if (p->flags & PKT_STREAM_MODIFIED) {
#ifdef COUNTERS
            t->replaced++;
#endif /* COUNTERS */
        }

#ifdef COUNTERS
        t->accepted++;
#endif /* COUNTERS */
    }

    ret = NFQVerdictCacheAdd(t, p, verdict);
    if (ret == 0) {
        NFQMutexUnlock(t);
        return TM_ECODE_OK;
    }

    do {
        switch (nfq_config.mode) {
            default:
            case NFQ_ACCEPT_MODE:
            case NFQ_ROUTE_MODE:
                if (p->flags & PKT_MARK_MODIFIED) {
#ifdef HAVE_NFQ_SET_VERDICT2
                    if (p->flags & PKT_STREAM_MODIFIED) {
                        ret = nfq_set_verdict2(t->qh, p->nfq_v.id, verdict,
                                p->nfq_v.mark,
                                GET_PKT_LEN(p), GET_PKT_DATA(p));
                    } else {
                        ret = nfq_set_verdict2(t->qh, p->nfq_v.id, verdict,
                                p->nfq_v.mark,
                                0, NULL);
                    }
#else /* fall back to old function */
                    if (p->flags & PKT_STREAM_MODIFIED) {
                        ret = nfq_set_verdict_mark(t->qh, p->nfq_v.id, verdict,
                                htonl(p->nfq_v.mark),
                                GET_PKT_LEN(p), GET_PKT_DATA(p));
                    } else {
                        ret = nfq_set_verdict_mark(t->qh, p->nfq_v.id, verdict,
                                htonl(p->nfq_v.mark),
                                0, NULL);
                    }
#endif /* HAVE_NFQ_SET_VERDICT2 */
                } else {
                    if (p->flags & PKT_STREAM_MODIFIED) {
                        ret = nfq_set_verdict(t->qh, p->nfq_v.id, verdict,
                                GET_PKT_LEN(p), GET_PKT_DATA(p));
                    } else {
                        ret = nfq_set_verdict(t->qh, p->nfq_v.id, verdict, 0, NULL);
                    }

                }
                break;
            case NFQ_REPEAT_MODE:
#ifdef HAVE_NFQ_SET_VERDICT2
                if (p->flags & PKT_STREAM_MODIFIED) {
                    ret = nfq_set_verdict2(t->qh, p->nfq_v.id, verdict,
                            (nfq_config.mark & nfq_config.mask) | (p->nfq_v.mark & ~nfq_config.mask),
                            GET_PKT_LEN(p), GET_PKT_DATA(p));
                } else {
                    ret = nfq_set_verdict2(t->qh, p->nfq_v.id, verdict,
                            (nfq_config.mark & nfq_config.mask) | (p->nfq_v.mark & ~nfq_config.mask),
                            0, NULL);
                }
#else /* fall back to old function */
                if (p->flags & PKT_STREAM_MODIFIED) {
                    ret = nfq_set_verdict_mark(t->qh, p->nfq_v.id, verdict,
                            htonl((nfq_config.mark & nfq_config.mask) | (p->nfq_v.mark & ~nfq_config.mask)),
                            GET_PKT_LEN(p), GET_PKT_DATA(p));
                } else {
                    ret = nfq_set_verdict_mark(t->qh, p->nfq_v.id, verdict,
                            htonl((nfq_config.mark & nfq_config.mask) | (p->nfq_v.mark & ~nfq_config.mask)),
                            0, NULL);
                }
#endif /* HAVE_NFQ_SET_VERDICT2 */
                break;
        }
    } while ((ret < 0) && (iter++ < NFQ_VERDICT_RETRY_TIME));

    NFQMutexUnlock(t);

    if (ret < 0) {
        SCLogWarning(SC_ERR_NFQ_SET_VERDICT,
                     "nfq_set_verdict of %p failed %" PRId32 ": %s",
                     p, ret, strerror(errno));
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

/**
 * \brief NFQ verdict module packet entry function
 */
TmEcode VerdictNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    NFQThreadVars *ntv = (NFQThreadVars *)data;
    /* update counters */
    CaptureStatsUpdate(tv, &ntv->stats, p);

    int ret;
    /* if this is a tunnel packet we check if we are ready to verdict
     * already. */
    if (IS_TUNNEL_PKT(p)) {
        SCLogDebug("tunnel pkt: %p/%p %s", p, p->root, p->root ? "upper layer" : "root");
        bool verdict = VerdictTunnelPacket(p);
        /* don't verdict if we are not ready */
        if (verdict == true) {
            ret = NFQSetVerdict(p->root ? p->root : p);
            if (ret != TM_ECODE_OK) {
                return ret;
            }
        }
    } else {
        /* no tunnel, verdict normally */
        ret = NFQSetVerdict(p);
        if (ret != TM_ECODE_OK) {
            return ret;
        }
    }
    return TM_ECODE_OK;
}

/**
 * \brief Decode a packet coming from NFQ
 */
TmEcode DecodeNFQ(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{

    IPV4Hdr *ip4h = (IPV4Hdr *)GET_PKT_DATA(p);
    IPV6Hdr *ip6h = (IPV6Hdr *)GET_PKT_DATA(p);
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (PKT_IS_PSEUDOPKT(p))
        return TM_ECODE_OK;

    DecodeUpdatePacketCounters(tv, dtv, p);

    if (IPV4_GET_RAW_VER(ip4h) == 4) {
        SCLogDebug("IPv4 packet");
        DecodeIPV4(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else if(IPV6_GET_RAW_VER(ip6h) == 6) {
        SCLogDebug("IPv6 packet");
        DecodeIPV6(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
    } else {
        SCLogDebug("packet unsupported by NFQ, first byte: %02x", *GET_PKT_DATA(p));
    }

    PacketDecodeFinalize(tv, dtv, p);

    return TM_ECODE_OK;
}

/**
 * \brief Initialize the NFQ Decode threadvars
 */
TmEcode DecodeNFQThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    return TM_ECODE_OK;
}

TmEcode DecodeNFQThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* NFQ */

