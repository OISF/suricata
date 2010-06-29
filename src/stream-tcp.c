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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * \todo - 4WHS: what if after the 2nd SYN we turn out to be normal 3WHS anyway?
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "threads.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-pool.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"
#include "stream-tcp.h"

#include "app-layer-parser.h"
#include "util-host-os-info.h"
#include "util-privs.h"

//#define DEBUG

typedef struct StreamTcpThread_ {
    uint64_t pkts;

    uint16_t counter_tcp_sessions;
    /** sessions not picked up because memcap was reached */
    uint16_t counter_tcp_ssn_memcap;

    TcpReassemblyThreadCtx *ra_ctx;         /**< tcp reassembly thread data */
} StreamTcpThread;

TmEcode StreamTcp (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode StreamTcpThreadInit(ThreadVars *, void *, void **);
TmEcode StreamTcpThreadDeinit(ThreadVars *, void *);
void StreamTcpExitPrintStats(ThreadVars *, void *);
static int ValidReset(TcpSession * , Packet *);
static int StreamTcpHandleFin(StreamTcpThread *, TcpSession *, Packet *);
void StreamTcpRegisterTests (void);
void StreamTcpReturnStreamSegments (TcpStream *);
void StreamTcpInitConfig(char);
extern void StreamTcpSegmentReturntoPool(TcpSegment *);
int StreamTcpGetFlowState(void *);
static int ValidTimestamp(TcpSession * , Packet *);
void StreamTcpSetOSPolicy(TcpStream*, Packet*);

#define STREAMTCP_DEFAULT_SESSIONS      262144
#define STREAMTCP_DEFAULT_PREALLOC      32768
#define STREAMTCP_DEFAULT_MEMCAP        64 * 1024 * 1024 /* 64mb */

#define STREAMTCP_NEW_TIMEOUT           60
#define STREAMTCP_EST_TIMEOUT           3600
#define STREAMTCP_CLOSED_TIMEOUT        120

#define STREAMTCP_EMERG_NEW_TIMEOUT     10
#define STREAMTCP_EMERG_EST_TIMEOUT     300
#define STREAMTCP_EMERG_CLOSED_TIMEOUT  20

static Pool *ssn_pool = NULL;
static SCMutex ssn_pool_mutex;
#ifdef DEBUG
static uint64_t ssn_pool_cnt = 0; /** counts ssns, protected by ssn_pool_mutex */
#endif

static SCSpinlock stream_memuse_spinlock;
static uint32_t stream_memuse;
static uint32_t stream_memuse_max;

void TmModuleStreamTcpRegister (void)
{
    tmm_modules[TMM_STREAMTCP].name = "StreamTcp";
    tmm_modules[TMM_STREAMTCP].ThreadInit = StreamTcpThreadInit;
    tmm_modules[TMM_STREAMTCP].Func = StreamTcp;
    tmm_modules[TMM_STREAMTCP].ThreadExitPrintStats = StreamTcpExitPrintStats;
    tmm_modules[TMM_STREAMTCP].ThreadDeinit = StreamTcpThreadDeinit;
    tmm_modules[TMM_STREAMTCP].RegisterTests = StreamTcpRegisterTests;
    tmm_modules[TMM_STREAMTCP].cap_flags = 0;
}

void StreamTcpIncrMemuse(uint32_t size) {
    SCSpinLock(&stream_memuse_spinlock);
    stream_memuse += size;
    if (stream_memuse > stream_memuse_max)
        stream_memuse_max = stream_memuse;
    SCSpinUnlock(&stream_memuse_spinlock);
}

void StreamTcpDecrMemuse(uint32_t size) {
    SCSpinLock(&stream_memuse_spinlock);
    if (size <= stream_memuse)
        stream_memuse -= size;
    else
        stream_memuse = 0;
    SCSpinUnlock(&stream_memuse_spinlock);
}

/** \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
int StreamTcpCheckMemcap(uint32_t size) {
    SCEnter();

    int ret = 0;
    SCSpinLock(&stream_memuse_spinlock);
    if (size + stream_memuse <= stream_config.memcap)
        ret = 1;
    SCSpinUnlock(&stream_memuse_spinlock);

    SCReturnInt(ret);
}

void StreamTcpReturnStreamSegments (TcpStream *stream)
{
    TcpSegment *seg = stream->seg_list;
    TcpSegment *next_seg;

    if (seg == NULL)
        return;

    while (seg != NULL) {
        next_seg = seg->next;
        StreamTcpSegmentReturntoPool(seg);
        seg = next_seg;
    }

    stream->seg_list = NULL;
    stream->seg_list_tail = NULL;
}

/** \brief Function to return the stream back to the pool. It returns the
 *         segments in the stream to the segment pool.
 *
 *  This function is called when the flow is destroyed, so it should free
 *  *everything* related to the tcp session. So including the app layer
 *  data. We are guaranteed to only get here when the flow's use_cnt is 0.
 *
 *  \param ssn Void ptr to the ssn.
 */
void StreamTcpSessionClear(void *ssnptr)
{
    SCEnter();
    StreamMsg *smsg = NULL;

    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        SCReturn;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    //AppLayerParserCleanupState(ssn);

    /* if we have (a) smsg(s), return to the pool */
    smsg = ssn->toserver_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toserver_smsg_head = NULL;

    smsg = ssn->toclient_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toclient_smsg_head = NULL;

    memset(ssn, 0, sizeof(TcpSession));
    SCMutexLock(&ssn_pool_mutex);
    PoolReturn(ssn_pool, ssn);
#ifdef DEBUG
    ssn_pool_cnt--;
#endif
    SCMutexUnlock(&ssn_pool_mutex);

    SCReturn;
}

/** \brief Function to return the stream segments back to the pool.
 *
 *  We don't clear out the app layer storage here as that is under protection
 *  of the "use_cnt" reference counter in the flow. This function is called
 *  when the use_cnt is always at least 1 (this pkt has incremented the flow
 *  use_cnt itself), so we don't bother.
 *
 *  \param p Packet used to identify the stream.
 */
static void StreamTcpSessionPktFree (Packet *p)
{
    SCEnter();

//    StreamMsg *smsg = NULL;

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL)
        SCReturn;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    /* if we have (a) smsg(s), return to the pool */
#if 0
    smsg = ssn->toserver_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toserver_smsg_head = NULL;

    smsg = ssn->toclient_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toclient_smsg_head = NULL;
#endif
    SCReturn;
}

/** \brief Stream alloc function for the Pool
 *  \param null NULL ptr (value of null is ignored)
 *  \retval ptr void ptr to TcpSession structure with all vars set to 0/NULL
 */
void *StreamTcpSessionPoolAlloc(void *null)
{
    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpSession)) == 0)
        return NULL;

    void *ptr = SCMalloc(sizeof(TcpSession));
    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(TcpSession));

    StreamTcpIncrMemuse((uint32_t)sizeof(TcpSession));

    return ptr;
}

/** \brief Pool free function
 *  \param s Void ptr to TcpSession memory */
void StreamTcpSessionPoolFree(void *s)
{
    StreamMsg *smsg = NULL;

    if (s == NULL)
        return;

    TcpSession *ssn = (TcpSession *)s;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    /* if we have (a) smsg(s), return to the pool */
    smsg = ssn->toserver_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toserver_smsg_head = NULL;

    smsg = ssn->toclient_smsg_head;
    while(smsg != NULL) {
        StreamMsg *smsg_next = smsg->next;
        SCLogDebug("returning smsg %p to pool", smsg);
        smsg->next = NULL;
        smsg->prev = NULL;
        smsg->flow = NULL;
        StreamMsgReturnToPool(smsg);
        smsg = smsg_next;
    }
    ssn->toclient_smsg_head = NULL;

    SCFree(ssn);

    StreamTcpDecrMemuse((uint32_t)sizeof(TcpSession));

}

/** \brief          To initialize the stream global configuration data
 *
 *  \param  quiet   It tells the mode of operation, if it is TRUE nothing will
 *                  be get printed.
 */

void StreamTcpInitConfig(char quiet)
{
    intmax_t value = 0;

    SCLogDebug("Initializing Stream");

    memset(&stream_config,  0, sizeof(stream_config));

    /** set config defaults */
    if ((ConfGetInt("stream.max_sessions", &value)) == 1) {
        stream_config.max_sessions = (uint32_t)value;
    } else {
        if (RunmodeIsUnittests())
            stream_config.max_sessions = 1024;
        else
            stream_config.max_sessions = STREAMTCP_DEFAULT_SESSIONS;
    }
    if (!quiet) {
        SCLogInfo("stream \"max_sessions\": %"PRIu32"", stream_config.max_sessions);
    }

    if ((ConfGetInt("stream.prealloc_sessions", &value)) == 1) {
        stream_config.prealloc_sessions = (uint32_t)value;
    } else {
        if (RunmodeIsUnittests())
            stream_config.prealloc_sessions = 128;
        else
            stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
    }
    if (!quiet) {
        SCLogInfo("stream \"prealloc_sessions\": %"PRIu32"", stream_config.prealloc_sessions);
    }

    if ((ConfGetInt("stream.memcap", &value)) == 1) {
        stream_config.memcap = (uint32_t)value;
    } else {
        stream_config.memcap = STREAMTCP_DEFAULT_MEMCAP;
    }
    if (!quiet) {
        SCLogInfo("stream \"memcap\": %"PRIu32"", stream_config.memcap);
    }

    if ((ConfGetBool("stream.midstream", &stream_config.midstream)) == 0) {
        stream_config.midstream = FALSE;/*In the final patch it will be FALSE*/
    }
    if (!quiet) {
        SCLogInfo("stream \"midstream\" session pickups: %s", stream_config.midstream ? "enabled" : "disabled");
    }

    if ((ConfGetBool("stream.async_oneside", &stream_config.async_oneside)) == 0)
    {
        stream_config.async_oneside = FALSE; /*In the final patch it will be FALSE*/
    }
    if (!quiet) {
        SCLogInfo("stream \"async_oneside\": %s", stream_config.async_oneside ? "enabled" : "disabled");
    }

    /* init the memcap and it's lock */
    stream_memuse = 0;
    stream_memuse_max = 0;
    SCSpinInit(&stream_memuse_spinlock, PTHREAD_PROCESS_PRIVATE);

    ssn_pool = PoolInit(stream_config.max_sessions,
                        stream_config.prealloc_sessions,
                        StreamTcpSessionPoolAlloc, NULL,
                        StreamTcpSessionPoolFree);
    if (ssn_pool == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "ssn_pool is not initialized");
        exit(EXIT_FAILURE);
    }

    SCMutexInit(&ssn_pool_mutex, NULL);

    StreamTcpReassembleInit(quiet);

    /* set the default TCP timeout, free function and flow state function
     * values. */
    //FlowSetProtoTimeout(IPPROTO_TCP, STREAMTCP_NEW_TIMEOUT,
    //                    STREAMTCP_EST_TIMEOUT, STREAMTCP_CLOSED_TIMEOUT);
    //FlowSetProtoEmergencyTimeout(IPPROTO_TCP, STREAMTCP_EMERG_NEW_TIMEOUT,
    //                             STREAMTCP_EMERG_EST_TIMEOUT,
    //                             STREAMTCP_EMERG_CLOSED_TIMEOUT);

    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);
    FlowSetFlowStateFunc(IPPROTO_TCP, StreamTcpGetFlowState);
}

void StreamTcpFreeConfig(char quiet)
{
    StreamTcpReassembleFree(quiet);

    if (ssn_pool != NULL) {
        PoolFree(ssn_pool);
        ssn_pool = NULL;
    } else {
        SCLogError(SC_ERR_POOL_EMPTY, "ssn_pool is NULL");
        exit(EXIT_FAILURE);
    }
    SCLogDebug("ssn_pool_cnt %"PRIu64"", ssn_pool_cnt);

    if (!quiet) {
        SCLogInfo("Max memuse of stream engine %"PRIu32" (in use %"PRIu32")",
            stream_memuse_max, stream_memuse);
    }
    SCMutexDestroy(&ssn_pool_mutex);

    SCSpinDestroy(&stream_memuse_spinlock);
}

/** \brief The function is used to to fetch a TCP session from the
 *         ssn_pool, when a TCP SYN is received.
 *
 *  \param quiet Packet P, which has been recieved for the new TCP session.
 *
 *  \retval TcpSession A new TCP session with field initilaized to 0/NULL.
 */
TcpSession *StreamTcpNewSession (Packet *p)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        SCMutexLock(&ssn_pool_mutex);
        p->flow->protoctx = PoolGet(ssn_pool);
#ifdef DEBUG
        if (p->flow->protoctx != NULL)
            ssn_pool_cnt++;
#endif
        SCMutexUnlock(&ssn_pool_mutex);

        ssn = (TcpSession *)p->flow->protoctx;
        if (ssn == NULL) {
            SCLogDebug("ssn_pool is empty");
            return NULL;
        }

        ssn->state = TCP_NONE;
    }

    return ssn;
}

static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn,
                                           uint8_t state)
{
    if (state == ssn->state)
        return;

    ssn->state = state;

    FlowUpdateQueue(p->flow);
}

/**
 *  \brief  Function to flip the direction When we missed the SYN packet,
 *          SYN/ACK is considered as sent by server, but our engine flagged the
 *          packet as from client for the host whose packet is received first in
 *          the session.
 *
 *  \param  ssn TcpSession to whom this packet belongs
 *  \param  p   Packet whose flag has to be changed
 */
static void StreamTcpPacketSwitchDir(TcpSession *ssn, Packet *p)
{
    SCLogDebug("ssn %p: switching pkt direction", ssn);

    if (PKT_IS_TOSERVER(p)) {
        p->flowflags &= ~FLOW_PKT_TOSERVER;
        p->flowflags |= FLOW_PKT_TOCLIENT;
    } else {
        p->flowflags &= ~FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_TOSERVER;
    }
}

/**
 *  \brief  Function to set the OS policy for the given stream based on the
 *          destination of the received packet.
 *
 *  \param  stream  TcpStream of which os_policy needs to set
 *  \param  p       Packet which is used to set the os policy
 */
void StreamTcpSetOSPolicy(TcpStream *stream, Packet *p)
{
    int ret = 0;

    if (PKT_IS_IPV4(p)) {
        /* Get the OS policy based on destination IP address, as destination
           OS will decide how to react on the anomalies of newly received
           packets */
        ret = SCHInfoGetIPv4HostOSFlavour((uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else
            stream->os_policy = OS_POLICY_DEFAULT;

    } else if (PKT_IS_IPV6(p)) {
        /* Get the OS policy based on destination IP address, as destination
           OS will decide how to react on the anomalies of newly received
           packets */
        ret = SCHInfoGetIPv6HostOSFlavour((uint8_t *)GET_IPV6_DST_ADDR(p));
        if (ret > 0)
            stream->os_policy = ret;
        else
            stream->os_policy = OS_POLICY_DEFAULT;
    }

    if (stream->os_policy == OS_POLICY_BSD_RIGHT)
        stream->os_policy = OS_POLICY_BSD;
    else if (stream->os_policy == OS_POLICY_OLD_SOLARIS)
        stream->os_policy = OS_POLICY_SOLARIS;

    SCLogDebug("Policy is %"PRIu8"", stream->os_policy);

}

/**
 *  \brief  Function to handle the TCP_CLOSED or NONE state. The function handles
 *          packets while the session state is None which means a newly
 *          initialized structure, or a fully closed session.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,
                                    StreamTcpThread *stt, TcpSession *ssn)
{
    switch (p->tcph->th_flags) {
        /* The following cases will allow us to create the tcp sessions in congestion
         * conditions, where the client open a connection with SYN and
         * any of the following flags:
         * TH_CWR -> Establish a new connection reducing window
         * TH_ECN -> Echo Congestion flag
         */
        case TH_SYN | TH_CWR | TH_ECN:
        case TH_SYN | TH_ECN:
        case TH_SYN | TH_CWR:
        case TH_SYN:
        {
            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL) {
                    SCPerfCounterIncr(stt->counter_tcp_ssn_memcap, tv->sc_perf_pca);
                    return -1;
                }

                SCPerfCounterIncr(stt->counter_tcp_sessions, tv->sc_perf_pca);
            }

            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

            /* set the sequence numbers and window */
            ssn->client.isn = TCP_GET_SEQ(p);
            ssn->client.ra_base_seq = ssn->client.isn;
            ssn->client.next_seq = ssn->client.isn + 1;

            /*Set the stream timestamp value, if packet has timestamp option
             * enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: p->tcpvars.ts %p, %02x", ssn, p->tcpvars.ts,
                           ssn->client.last_ts);

                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
                ssn->client.last_pkt_ts = p->ts.tv_sec;
                ssn->client.flags |= STREAMTCP_FLAG_TIMESTAMP;
            }


            ssn->server.window = TCP_GET_WINDOW(p);
            if (p->tcpvars.ws != NULL) {
                ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = TCP_GET_WSCALE(p);
            }

            SCLogDebug("ssn %p: ssn->client.isn %" PRIu32 ", "
                       "ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack "
                       "%"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq,
                       ssn->client.last_ack);
            break;
        }
        case TH_SYN|TH_ACK:
        case TH_SYN|TH_ACK|TH_ECN:
            if (stream_config.midstream == FALSE &&
                    stream_config.async_oneside == FALSE)
                break;

            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL) {
                    SCPerfCounterIncr(stt->counter_tcp_ssn_memcap, tv->sc_perf_pca);
                    return -1;
                }
                SCPerfCounterIncr(stt->counter_tcp_sessions, tv->sc_perf_pca);
            }
            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                       "TCP_SYN_RECV", ssn);
            ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;
            /* Flag used to change the direct in the later stage in the session */
            ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_SYNACK;

            /* sequence number & window */
            ssn->server.isn = TCP_GET_SEQ(p);
            ssn->server.ra_base_seq = ssn->server.isn;
            ssn->server.next_seq = ssn->server.isn + 1;
            ssn->server.window = TCP_GET_WINDOW(p);
            SCLogDebug("ssn %p: server window %u", ssn, ssn->server.window);

            ssn->client.isn = TCP_GET_ACK(p) - 1;
            ssn->client.ra_base_seq = ssn->client.isn;
            ssn->client.next_seq = ssn->client.isn + 1;

            ssn->client.last_ack = TCP_GET_ACK(p);
            /** If the client has a wscale option the server had it too,
             *  so set the wscale for the server to max. Otherwise none
             *  will have the wscale opt just like it should. */
            if (p->tcpvars.ws != NULL) {
                ssn->client.wscale = TCP_GET_WSCALE(p);
                ssn->server.wscale = TCP_WSCALE_MAX;
            }

            SCLogDebug("ssn %p: ssn->client.isn %"PRIu32", ssn->client.next_seq"
                       " %"PRIu32", ssn->client.last_ack %"PRIu32"", ssn,
                       ssn->client.isn, ssn->client.next_seq,
                       ssn->client.last_ack);
            SCLogDebug("ssn %p: ssn->server.isn %"PRIu32", ssn->server.next_seq"
                       " %"PRIu32", ssn->server.last_ack %"PRIu32"", ssn,
                       ssn->server.isn, ssn->server.next_seq,
                       ssn->server.last_ack);

            /* Set the timestamp value for both streams, if packet has timestamp
             * option enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                ssn->client.last_ts = TCP_GET_TSECR(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                           "ssn->client.last_ts %" PRIu32"", ssn,
                           ssn->server.last_ts, ssn->client.last_ts);

                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

                ssn->server.last_pkt_ts = p->ts.tv_sec;
                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;

            } else {
                ssn->server.last_ts = 0;
                ssn->client.last_ts = 0;
            }

            break;
        /* Handle SYN/ACK and 3WHS shake missed together as it is almost
         * similar. */
        case TH_ACK:
        case TH_ACK|TH_ECN:
        case TH_ACK|TH_PUSH:
        case TH_ACK|TH_PUSH|TH_ECN:
            if (stream_config.midstream == FALSE)
                break;
            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL) {
                    SCPerfCounterIncr(stt->counter_tcp_ssn_memcap, tv->sc_perf_pca);
                    return -1;
                }
                SCPerfCounterIncr(stt->counter_tcp_sessions, tv->sc_perf_pca);
            }
            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                       "TCP_ESTABLISHED", ssn);

            ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
            ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;

            /* set the sequence numbers and window */
            ssn->client.isn = TCP_GET_SEQ(p) - 1;
            ssn->client.ra_base_seq = ssn->client.isn;
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            ssn->client.window = TCP_GET_WINDOW(p);
            ssn->client.last_ack = TCP_GET_SEQ(p);
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            SCLogDebug("ssn %p: ssn->client.isn %u, ssn->client.next_seq %u",
                    ssn, ssn->client.isn, ssn->client.next_seq);

            ssn->server.isn = TCP_GET_ACK(p) - 1;
            ssn->server.ra_base_seq = ssn->server.isn;
            ssn->server.next_seq = ssn->server.isn + 1;
            ssn->server.last_ack = TCP_GET_ACK(p);
            ssn->server.next_win = ssn->server.last_ack;

             SCLogDebug("ssn %p: ssn->client.next_win %"PRIu32", "
                        "ssn->server.next_win %"PRIu32"", ssn,
                        ssn->client.next_win, ssn->server.next_win);
             SCLogDebug("ssn %p: ssn->client.last_ack %"PRIu32", "
                        "ssn->server.last_ack %"PRIu32"", ssn,
                        ssn->client.last_ack, ssn->server.last_ack);

            /** window scaling for midstream pickups, we can't do much other
             *  than assume that it's set to the max value: 14 */
            ssn->client.wscale = TCP_WSCALE_MAX;
            ssn->server.wscale = TCP_WSCALE_MAX;

            /* Set the timestamp value for both streams, if packet has timestamp
             * option enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                ssn->server.last_ts = TCP_GET_TSECR(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                           "ssn->client.last_ts %" PRIu32"", ssn,
                           ssn->server.last_ts, ssn->client.last_ts);

                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

                ssn->client.last_pkt_ts = p->ts.tv_sec;
                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;

            } else {
                ssn->server.last_ts = 0;
                ssn->client.last_ts = 0;
            }

            StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);

            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:
        case TH_RST|TH_ACK|TH_PUSH:
        case TH_RST|TH_ACK|TH_PUSH|TH_ECN:
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_ECN:
        case TH_FIN|TH_ACK|TH_PUSH:
        case TH_FIN|TH_ACK|TH_PUSH|TH_ECN:
            BUG_ON(p->flow->protoctx != NULL);
            SCLogDebug("FIN or RST packet received, no session setup");
            break;
        default:
            SCLogDebug("default case");
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
 *          SYN, SYN/ACK, RSTpackets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p,
                                       StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ?
               "toclient":"toserver");

    switch (p->tcph->th_flags) {
        case TH_SYN:
        case TH_SYN|TH_CWR:
        case TH_SYN|TH_CWR|TH_ECN:
            SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);
            if (ssn->flags & STREAMTCP_FLAG_4WHS)
                SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent of "
                           "4WHS SYN", ssn);

            if (PKT_IS_TOCLIENT(p)) {
                /** a SYN only packet in the opposite direction could be:
                 *  http://www.breakingpointsystems.com/community/blog/tcp-
                 *  portals-the-three-way-handshake-is-a-lie
                 *
                 * \todo improve resetting the session */

                /* indicate that we're dealing with 4WHS here */
                ssn->flags |= STREAMTCP_FLAG_4WHS;
                SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS flag set", ssn);

                /* set the sequence numbers and window for server
                 * We leave the ssn->client.isn in place as we will
                 * check the SYN/ACK pkt with that.
                 */
                ssn->server.isn = TCP_GET_SEQ(p);
                ssn->server.ra_base_seq = ssn->server.isn;
                ssn->server.next_seq = ssn->server.isn + 1;

                /* Set the stream timestamp value, if packet has timestamp
                 * option enabled. */
                if (p->tcpvars.ts != NULL) {
                    ssn->server.last_ts = TCP_GET_TSVAL(p);
                    SCLogDebug("ssn %p: p->tcpvars.ts %p, %02x", ssn,
                                p->tcpvars.ts, ssn->server.last_ts);

                    if (ssn->server.last_ts == 0)
                        ssn->server.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
                    ssn->server.last_pkt_ts = p->ts.tv_sec;
                    ssn->server.flags |= STREAMTCP_FLAG_TIMESTAMP;
                }

                ssn->server.window = TCP_GET_WINDOW(p);
                if (p->tcpvars.ws != NULL) {
                    ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                    ssn->server.wscale = TCP_GET_WSCALE(p);
                }

                SCLogDebug("ssn %p: 4WHS ssn->server.isn %" PRIu32 ", "
                           "ssn->server.next_seq %" PRIu32 ", "
                           "ssn->server.last_ack %"PRIu32"", ssn,
                           ssn->server.isn, ssn->server.next_seq,
                           ssn->server.last_ack);
                SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                           "ssn->client.next_seq %" PRIu32 ", "
                           "ssn->client.last_ack %"PRIu32"", ssn,
                           ssn->client.isn, ssn->client.next_seq,
                           ssn->client.last_ack);
            }

            break;
        case TH_SYN|TH_ACK:
        case TH_SYN|TH_ACK|TH_ECN:
            if (ssn->flags & STREAMTCP_FLAG_4WHS && PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: SYN/ACK received on 4WHS session", ssn);

                /* Check if the SYN/ACK packet ack's the earlier
                 * received SYN packet. */
                if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->server.isn + 1))) {
                    SCLogDebug("ssn %p: 4WHS ACK mismatch, packet ACK %"PRIu32""
                               " != %" PRIu32 " from stream", ssn,
                               TCP_GET_ACK(p), ssn->server.isn + 1);
                    return -1;
                }

                /* Check if the SYN/ACK packet SEQ's the *FIRST* received SYN
                 * packet. */
                if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
                    SCLogDebug("ssn %p: 4WHS SEQ mismatch, packet SEQ %"PRIu32""
                               " != %" PRIu32 " from *first* SYN pkt", ssn,
                               TCP_GET_SEQ(p), ssn->client.isn);
                    return -1;
                }


                /* update state */
                StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
                SCLogDebug("ssn %p: =~ 4WHS ssn state is now TCP_SYN_RECV", ssn);

                /* sequence number & window */
                ssn->client.isn = TCP_GET_SEQ(p);
                ssn->client.ra_base_seq = ssn->client.isn;
                ssn->client.next_seq = ssn->client.isn + 1;

                ssn->server.window = TCP_GET_WINDOW(p);
                SCLogDebug("ssn %p: 4WHS window %" PRIu32 "", ssn,
                            ssn->client.window);

                /* Set the timestamp values used to validate the timestamp of
                 * received packets. */
                if ((p->tcpvars.ts != NULL) && (ssn->server.flags &
                                                   STREAMTCP_FLAG_TIMESTAMP))
                {
                    ssn->client.last_ts = TCP_GET_TSVAL(p);
                    SCLogDebug("ssn %p: 4WHS ssn->client.last_ts %" PRIu32" "
                               "ssn->server.last_ts %" PRIu32"", ssn,
                               ssn->client.last_ts, ssn->server.last_ts);
                    ssn->server.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                    ssn->client.last_pkt_ts = p->ts.tv_sec;
                    if (ssn->client.last_ts == 0)
                        ssn->client.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
                } else {
                    ssn->server.last_ts = 0;
                    ssn->client.last_ts = 0;
                    ssn->server.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    ssn->server.flags &= ~STREAMTCP_FLAG_ZERO_TIMESTAMP;
                }

                ssn->server.last_ack = TCP_GET_ACK(p);
                ssn->client.last_ack = ssn->client.isn + 1;

                /** check for the presense of the ws ptr to determine if we
                 *  support wscale at all */
                if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
                        (p->tcpvars.ws != NULL))
                {
                    ssn->server.wscale = TCP_GET_WSCALE(p);
                } else {
                    ssn->server.wscale = 0;
                }

                ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                SCLogDebug("ssn %p: 4WHS ssn->client.next_win %" PRIu32 "", ssn,
                            ssn->client.next_win);
                SCLogDebug("ssn %p: 4WHS ssn->server.next_win %" PRIu32 "", ssn,
                            ssn->server.next_win);
                SCLogDebug("ssn %p: 4WHS ssn->client.isn %" PRIu32 ", "
                           "ssn->client.next_seq %" PRIu32 ", "
                           "ssn->client.last_ack %" PRIu32 " "
                           "(ssn->server.last_ack %" PRIu32 ")", ssn,
                           ssn->client.isn, ssn->client.next_seq,
                           ssn->client.last_ack, ssn->server.last_ack);

                /* done here */
                break;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
                return -1;
            }

            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                           "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                            ssn->client.isn + 1);
                return -1;
            }

            /* update state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);

            /* sequence number & window */
            ssn->server.isn = TCP_GET_SEQ(p);
            ssn->server.ra_base_seq = ssn->server.isn;
            ssn->server.next_seq = ssn->server.isn + 1;

            ssn->client.window = TCP_GET_WINDOW(p);
            SCLogDebug("ssn %p: window %" PRIu32 "", ssn, ssn->server.window);

            /* Set the timestamp values used to validate the timestamp of
             * received packets.*/
            if ((p->tcpvars.ts != NULL) &&
                    (ssn->client.flags & STREAMTCP_FLAG_TIMESTAMP))
            {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                           "ssn->client.last_ts %" PRIu32"", ssn,
                           ssn->server.last_ts, ssn->client.last_ts);
                ssn->client.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                ssn->server.last_pkt_ts = p->ts.tv_sec;
                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_FLAG_ZERO_TIMESTAMP;
            } else {
                ssn->client.last_ts = 0;
                ssn->server.last_ts = 0;
                ssn->client.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.flags &= ~STREAMTCP_FLAG_ZERO_TIMESTAMP;
            }

            ssn->client.last_ack = TCP_GET_ACK(p);
            ssn->server.last_ack = ssn->server.isn + 1;

            /** check for the presense of the ws ptr to determine if we
             *  support wscale at all */
            if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
                    (p->tcpvars.ws != NULL))
            {
                ssn->client.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->client.wscale = 0;
            }

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn,
                        ssn->server.next_win);
            SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn,
                        ssn->client.next_win);
            SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", "
                       "ssn->server.next_seq %" PRIu32 ", "
                       "ssn->server.last_ack %" PRIu32 " "
                       "(ssn->client.last_ack %" PRIu32 ")", ssn,
                       ssn->server.isn, ssn->server.next_seq,
                       ssn->server.last_ack, ssn->client.last_ack);

            /* unset the 4WHS flag as we received this SYN/ACK as part of a
             * (so far) valid 3WHS */
            if (ssn->flags & STREAMTCP_FLAG_4WHS)
                SCLogDebug("ssn %p: STREAMTCP_FLAG_4WHS unset, normal SYN/ACK"
                           " so considering 3WHS", ssn);

            ssn->flags &=~ STREAMTCP_FLAG_4WHS;
            break;
        case TH_ACK:
        case TH_ACK|TH_ECN:
        case TH_ACK|TH_PUSH:
        case TH_ACK|TH_PUSH|TH_ECN:
            /* Handle the asynchronous stream, when we receive a  SYN packet
             and now istead of receving a SYN/ACK we receive a ACK from the
             same host, which sent the SYN, this suggests the ASNYC streams.*/
            if (stream_config.async_oneside == FALSE)
                break;

            /* Check if the ACK packet seq no is equal to the expected seq. no.*/
            /*XXX GS what if we missed the initial ACK here, then we can't setup
              the session. I was thinking to check the SEQ_GEQ instead of SEQ_EQ
              your thoughts ?? It will quite relax then in checking.*/
            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
                SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                           "%" PRIu32 " from stream",ssn, TCP_GET_SEQ(p),
                           ssn->client.next_seq);
                return -1;
            }

            ssn->flags |= STREAMTCP_FLAG_ASYNC;
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            ssn->client.window = TCP_GET_WINDOW(p);
            ssn->client.last_ack = TCP_GET_SEQ(p);
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            /* Set the server side parameters */
            ssn->server.isn = TCP_GET_ACK(p) - 1;
            ssn->server.ra_base_seq = ssn->server.isn;
            ssn->server.next_seq = ssn->server.isn + 1;
            ssn->server.last_ack = ssn->server.next_seq;
            ssn->server.next_win = ssn->server.last_ack;

            SCLogDebug("ssn %p: synsent => Asynchronous stream, packet SEQ"
                       " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                            "ssn->client.next_seq %" PRIu32 ""
                            ,ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                            + p->payload_len, ssn->client.next_seq);

            ssn->client.wscale = TCP_WSCALE_MAX;
            ssn->server.wscale = TCP_WSCALE_MAX;

             /*Set the timestamp values used to validate the timestamp of received
              packets.*/
            if (p->tcpvars.ts != NULL &&
                    (ssn->client.flags & STREAMTCP_FLAG_TIMESTAMP))
            {
                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.last_pkt_ts = p->ts.tv_sec;
            } else {
                ssn->client.last_ts = 0;
                ssn->client.flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.flags &= ~STREAMTCP_FLAG_ZERO_TIMESTAMP;
            }

            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:
            if(ValidReset(ssn, p)){
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) &&
                        SEQ_EQ(TCP_GET_WINDOW(p), 0) &&
                        SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1)))
                {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: Reset received and state changed to "
                               "TCP_CLOSED", ssn);
                    StreamTcpSessionPktFree(p);
                }
            } else
                return -1;
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_SYN_RECV state. The function handles
 *          SYN, SYN/ACK, ACK, FIN, RST packets and correspondingly changes
 *          the connection state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p,
                                       StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_SYN:
        case TH_SYN|TH_CWR:
        case TH_SYN|TH_CWR|TH_ECN:
            SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);
            break;
        case TH_SYN|TH_ACK:
        case TH_SYN|TH_ACK|TH_ECN:
            SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);
            break;
        case TH_ACK:
        case TH_ACK|TH_ECN:
        case TH_ACK|TH_PUSH:
        case TH_ACK|TH_PUSH|TH_ECN:
            /* If the timestamp option is enabled for both the streams, then
             * validate the received packet timestamp value against the
             * stream->last_ts. If the timestamp is valid then process the
             * packet normally otherwise the drop the packet (RFC 1323)*/
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (ssn->flags & STREAMTCP_FLAG_4WHS && PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: ACK received on 4WHS session",ssn);

                if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))) {
                    SCLogDebug("4WHS normal pkt");

                    ssn->client.last_ack = TCP_GET_ACK(p);
                    ssn->server.next_seq += p->payload_len;
                    ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                    ssn->client.next_win = ssn->client.last_ack +
                                                             ssn->client.window;

                    StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                            &ssn->server, p);
                } else {
                    SCLogDebug("ssn %p: 4WHS wrong seq nr on packet", ssn);
                    return -1;
                }

                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                           TCP_GET_SEQ(p), TCP_GET_ACK(p));

                StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
                SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

                SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 ", "
                           "ssn->client.last_ack %"PRIu32"", ssn,
                           ssn->client.next_win, ssn->client.last_ack);
                break;
            }

            /* Check if the ACK received is in right direction. But when we have
             * picked up a mid stream session after missing the initial SYN pkt,
             * in this case the ACK packet can arrive from either client (normal
             * case) or from server itself (asynchronous streams). Therefore
             *  the check has been avoided in this case */
            if (PKT_IS_TOCLIENT(p)) {
                /* special case, handle 4WHS, so SYN/ACK in the opposite
                 * direction */
                if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK) {
                    SCLogDebug("ssn %p: ACK received on midstream SYN/ACK "
                               "pickup session",ssn);
                    /* fall through */
                } else {
                    SCLogDebug("ssn %p: ACK received in the wrong direction",
                                ssn);
                    return -1;
                }
            }

            if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
                SCLogDebug("normal pkt");

                /* process the packet normal, No Async streams :) */

                ssn->server.last_ack = TCP_GET_ACK(p);
                ssn->client.next_seq += p->payload_len;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

                if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                    ssn->client.window = TCP_GET_WINDOW(p);
                    ssn->server.next_win = ssn->server.last_ack +
                                                            ssn->server.window;
                    /* window scaling for midstream pickups, we can't do much
                     * other than assume that it's set to the max value: 14 */
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                }

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                     &ssn->client, p);

              /* If asynchronous stream handling is allowed then set the session,
                 if packet's seq number is equal the expected seq no.*/
            } else if (stream_config.async_oneside == TRUE &&
                    (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)))
            {
                /*set the ASYNC flag used to indicate the session as async stream
                  and helps in relaxing the windows checks.*/
                ssn->flags |= STREAMTCP_FLAG_ASYNC;
                ssn->server.next_seq += p->payload_len;
                ssn->server.last_ack = TCP_GET_SEQ(p);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                ssn->client.last_ack = TCP_GET_ACK(p);

                if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                    ssn->server.window = TCP_GET_WINDOW(p);
                    ssn->client.next_win = ssn->server.last_ack +
                                                            ssn->server.window;
                    /* window scaling for midstream pickups, we can't do much
                     * other than assume that it's set to the max value: 14 */
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                }

                SCLogDebug("ssn %p: synrecv => Asynchronous stream, packet SEQ"
                        " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                        "ssn->server.next_seq %" PRIu32 "\n"
                        , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                        + p->payload_len, ssn->server.next_seq);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                     &ssn->server, p);

            } else {
                SCLogDebug("ssn %p: wrong seq nr on packet", ssn);
                return -1;
            }

            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ""
                       ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                       TCP_GET_ACK(p));

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", "
                       "ssn->server.last_ack %"PRIu32"", ssn,
                       ssn->server.next_win, ssn->server.last_ack);

            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:

            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received and state changed to "
                               "TCP_CLOSED", ssn);

                StreamTcpSessionPktFree(p);
            } else
                return -1;
            break;
        case TH_FIN:

            /*FIN is handled in the same way as in TCP_ESTABLISHED case */;
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if((StreamTcpHandleFin(stt, ssn, p)) == -1)
                return -1;
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the client to server. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembling.
 *
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToServer(TcpSession *ssn, Packet *p,
                                            StreamTcpThread *stt)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
               "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    if (!(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {

            SCLogDebug("ssn %p: server => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    "%" PRIu32"(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")",
                    ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    +p->payload_len, ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win,
                    ssn->client.ra_base_seq);

            /*update the last_ack to current seq number as the session is
              async and other stream is not updating it anymore :(*/
            ssn->client.last_ack = TCP_GET_SEQ(p);

        } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {

            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ."
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")"
                    , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    +p->payload_len, ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win,
                    ssn->client.ra_base_seq);

            /*it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :(*/
            ssn->client.last_ack = TCP_GET_SEQ(p);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        } else if (SEQ_EQ(ssn->client.last_ack, (ssn->client.isn + 1)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {

            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")"
                    , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    +p->payload_len, ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win,
                    ssn->client.ra_base_seq);

            /*it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :(*/
            ssn->client.last_ack = TCP_GET_SEQ(p);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        } else {

            SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")"
                    , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    +p->payload_len, ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win,
                    ssn->client.ra_base_seq);

            return -1;
        }
    }

    if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
        ssn->client.next_seq += p->payload_len;
        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                    ssn, ssn->client.next_seq);
    }

    if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
            ssn->flags & STREAMTCP_FLAG_ASYNC)
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win"
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn,
                    ssn->server.window);

        if (SEQ_GT(TCP_GET_ACK(p), ssn->server.last_ack))
            ssn->server.last_ack = TCP_GET_ACK(p);

        if (SEQ_GT((ssn->server.last_ack + ssn->server.window),
                ssn->server.next_win))
        {
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            SCLogDebug("ssn %p: seq %"PRIu32", updated ssn->server.next_win"
                    "%" PRIu32 " (win %"PRIu32")", ssn, TCP_GET_SEQ(p),
                    ssn->server.next_win, ssn->server.window);
        }

        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
    } else {
        SCLogDebug("ssn %p: toserver => SEQ out of window, packet SEQ "
                "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                "%" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")",
                ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                +p->payload_len, ssn->client.last_ack, ssn->client.next_win,
                TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win,
                ssn->client.ra_base_seq);
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the server to client. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembling.
 *
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToClient(TcpSession *ssn, Packet *p,
                                            StreamTcpThread *stt)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ","
               " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    /* To get the server window value from the servers packet, when connection
       is picked up as midstream */
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(p);
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to"
                " %" PRIu32 "", ssn, ssn->server.next_win);
    }

    if (!(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {

            SCLogDebug("ssn %p: client => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    " %"PRIu32"(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")",
                    ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    +p->payload_len, ssn->server.last_ack, ssn->server.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win,
                    ssn->server.ra_base_seq);

            ssn->server.last_ack = TCP_GET_SEQ(p);

        } else {
            return -1;
        }
    }

    if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
        ssn->server.next_seq += p->payload_len;
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                ssn, ssn->server.next_seq);
    }

    if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) ||
            (ssn->flags & STREAMTCP_FLAG_ASYNC)) {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win"
                " %" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn,
                    ssn->client.window);

        if (SEQ_GT(TCP_GET_ACK(p), ssn->client.last_ack))
            ssn->client.last_ack = TCP_GET_ACK(p);

        if (SEQ_GT((ssn->client.last_ack + ssn->client.window),
                ssn->client.next_win))
        {
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            SCLogDebug("ssn %p: seq %"PRIu32", updated ssn->client.next_win"
                       " %" PRIu32 " (win %"PRIu32")", ssn, TCP_GET_SEQ(p),
                        ssn->client.next_win, ssn->client.window);
        } else {
            SCLogDebug("ssn %p: seq %"PRIu32", keeping ssn->client.next_win"
                       " %" PRIu32 " the same (win %"PRIu32")", ssn,
                       TCP_GET_SEQ(p),ssn->client.next_win, ssn->client.window);
        }

        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
    } else {
        SCLogDebug("ssn %p: client => SEQ out of window, packet SEQ"
                   "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                   " ssn->server.last_ack %" PRIu32 ", ssn->server.next_win "
                   "%" PRIu32 "(%"PRIu32") (ssn->server.ra_base_seq %"PRIu32")",
                    ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) +
                    p->payload_len, ssn->server.last_ack, ssn->server.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win,
                    ssn->server.ra_base_seq);
    }
    return 0;
}
/**
 *  \brief  Function to handle the TCP_ESTABLISHED state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state. The function handles the data inside packets and call
 *          StreamTcpReassembleHandleSegment() to handle the reassembling.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p,
                                           StreamTcpThread *stt,
                                           TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_SYN:
        case TH_SYN|TH_CWR:
        case TH_SYN|TH_CWR|TH_ECN:
            SCLogDebug("ssn %p: SYN packet on state ESTABLISED... resent", ssn);
            break;
        case TH_SYN|TH_ACK:
        case TH_SYN|TH_ACK|TH_ECN:
            SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent",
                        ssn);
            break;
        case TH_ACK:
        case TH_ACK|TH_ECN:
        case TH_ACK|TH_PUSH:
        case TH_ACK|TH_PUSH|TH_ECN:

            /* If the timestamp option is enabled for both the streams, then
             * validate the received packet timestamp value against the
             * stream->last_ts. If the timestamp is valid then process the
             * packet normally otherwise the drop the packet (RFC 1323) */
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                /* Process the received packet to server */
                HandleEstablishedPacketToServer(ssn, p, stt);

                SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                           " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                            ssn->client.next_seq, ssn->server.last_ack
                            ,ssn->client.next_win, ssn->client.window);

            } else { /* implied to client */

                /* Process the received packet to client */
                HandleEstablishedPacketToClient(ssn, p, stt);

                SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                           " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                            ssn->server.next_seq, ssn->client.last_ack,
                            ssn->server.next_win, ssn->server.window);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_ECN:
        case TH_FIN|TH_ACK|TH_PUSH:
        case TH_FIN|TH_ACK|TH_PUSH|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            SCLogDebug("StreamTcpPacketStateEstablished (%p): FIN received SEQ"
                       " %" PRIu32 ", last ACK %" PRIu32 ", next win %"PRIu32","
                       " win %" PRIu32 "", ssn, ssn->server.next_seq,
                       ssn->client.last_ack, ssn->server.next_win,
                       ssn->server.window);

            if((StreamTcpHandleFin(stt, ssn, p)) == -1)
                return -1;
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:

            if(ValidReset(ssn, p)) {
                if(PKT_IS_TOSERVER(p)) {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: Reset received and state changed to "
                               "TCP_CLOSED", ssn);

                    ssn->client.next_seq = TCP_GET_ACK(p);
                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                                ssn->server.next_seq);
                    ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                        ssn->server.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                         &ssn->client, p);
                    SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                               "%" PRIu32 "", ssn, ssn->client.next_seq,
                               ssn->server.last_ack);
                    StreamTcpSessionPktFree(p);
                } else {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: Reset received and state changed to "
                               "TCP_CLOSED", ssn);

                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    ssn->client.next_seq = TCP_GET_ACK(p);

                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                                ssn->server.next_seq);
                    ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                        ssn->client.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                         &ssn->server, p);
                    SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                               "%" PRIu32 "", ssn, ssn->server.next_seq,
                               ssn->client.last_ack);

                    StreamTcpSessionPktFree(p);
                }
            } else
                return -1;
            break;
         default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the FIN packets for states TCP_SYN_RECV and
 *          TCP_ESTABLISHED and changes to another TCP state as required.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpHandleFin(StreamTcpThread *stt, TcpSession *ssn, Packet *p)
{

    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
                   " ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                   TCP_GET_ACK(p));

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
            SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
        {
              SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                         "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                          ssn->client.next_seq);
              return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        ssn->server.next_seq = TCP_GET_ACK(p);
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
            ssn->server.last_ack = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { /* implied to client */
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", "
                   "ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                    TCP_GET_ACK(p));
        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                   SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack +
                                                ssn->server.window)))
        {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                       "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                        ssn->server.next_seq);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))
            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        ssn->client.next_seq = TCP_GET_ACK(p);
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
            ssn->client.last_ack = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->server.next_seq, ssn->client.last_ack);
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT1 state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p,
                                        StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_ACK:
        case TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                           TCP_GET_SEQ(p), TCP_GET_ACK(p));

                StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                     &ssn->client, p);

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    ssn->client.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                            ssn, ssn->client.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);
            } else { /* implied to client */
                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                           TCP_GET_SEQ(p), TCP_GET_ACK(p));
                StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);

                SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                     &ssn->server, p);

                if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                    ssn->server.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                            ssn, ssn->server.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_ECN:
        case TH_FIN|TH_ACK|TH_PUSH:
        case TH_FIN|TH_ACK|TH_PUSH|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack +
                                                         ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                     &ssn->client, p);

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    ssn->client.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                            ssn, ssn->client.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack +
                                                          ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                        &ssn->server, p);

                if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                    ssn->server.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                            ssn, ssn->server.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:

            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                            ssn);

                StreamTcpSessionPktFree(p);
            }
            else
                return -1;
            break;
        default:
            SCLogDebug("ssn (%p): default case", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT2 state. The function handles
 *          ACK, RST, FIN packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait2(ThreadVars *tv, Packet *p,
                                        StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_ACK:
        case TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                        &ssn->client, p);

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    ssn->client.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "",
                            ssn, ssn->client.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                            ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);

                if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                    ssn->server.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "",
                            ssn, ssn->server.next_seq);
                }

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
        case TH_RST|TH_ACK|TH_ECN:

            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED",
                            ssn);

                StreamTcpSessionPktFree(p);
            }
            else
                return -1;
            break;
        case TH_FIN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack +
                                                        ssn->client.window))))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                               "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                            ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack +
                                                        ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                               "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                            ssn->client.last_ack);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSING state. Upon arrival of ACK
 *          the connection goes to TCP_TIME_WAIT state. The state has been
 *          reached as both end application has been closed.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateClosing(ThreadVars *tv, Packet *p,
                                       StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:
        case TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                            ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                               TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);
                SCLogDebug("StreamTcpPacketStateClosing (%p): =+ next SEQ "
                           "%" PRIu32 ", last ACK %" PRIu32 "", ssn,
                           ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSE_WAIT state. Upon arrival of FIN
 *          packet from server the connection goes to TCP_LAST_ACK state.
 *          The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateCloseWait(ThreadVars *tv, Packet *p,
                                         StreamTcpThread *stt, TcpSession *ssn)
{
    SCEnter();
    if (ssn == NULL)
        SCReturnInt(-1);
    if (PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));
    } else {
         SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));
    }

    switch(p->tcph->th_flags) {
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    SCReturnInt(-1);
            }

            if (PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack +
                                                         ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    SCReturnInt(-1);
                }

                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);
            } else {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack +
                                                         ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    SCReturnInt(-1);
                }

                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);
            }
            break;
        case TH_ACK:
        case TH_ACK|TH_ECN:
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    SCReturnInt(-1);
            }

            if (PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack +
                                                         ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    SCReturnInt(-1);
                }
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);
            } else {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack +
                                                         ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    SCReturnInt(-1);
                }
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }
    SCReturnInt(0);
}

/**
 *  \brief  Function to handle the TCP_LAST_ACK state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool. The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPakcetStateLastAck(ThreadVars *tv, Packet *p,
                                       StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:
        case TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);

                StreamTcpSessionPktFree(p);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_TIME_WAIT state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateTimeWait(ThreadVars *tv, Packet *p,
                                        StreamTcpThread *stt, TcpSession *ssn)
{
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:
        case TH_ACK|TH_ECN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->client.next_seq,
                           ssn->server.last_ack);

                StreamTcpSessionPktFree(p);
            } else {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                           "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                            TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                               " != %" PRIu32 " from stream", ssn,
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn,
                                                          &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                           "%" PRIu32 "", ssn, ssn->server.next_seq,
                           ssn->client.last_ack);

                StreamTcpSessionPktFree(p);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;

    }
    return 0;
}

/* flow is and stays locked */
static int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt)
{
    SCEnter();
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone(tv, p, stt, ssn) == -1)
            SCReturnInt(-1);

        if (ssn != NULL)
            SCLogDebug("ssn->alproto %"PRIu16"", p->flow->alproto);
    } else {
        /* check if the packet is in right direction, when we missed the
           SYN packet and picked up midstream session. */
        if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)
            StreamTcpPacketSwitchDir(ssn, p);

        switch (ssn->state) {
            case TCP_SYN_SENT:
                if(StreamTcpPacketStateSynSent(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_SYN_RECV:
                if(StreamTcpPacketStateSynRecv(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_ESTABLISHED:
                if(StreamTcpPacketStateEstablished(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_FIN_WAIT1:
                if(StreamTcpPacketStateFinWait1(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_FIN_WAIT2:
                if(StreamTcpPacketStateFinWait2(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_CLOSING:
                if(StreamTcpPacketStateClosing(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_CLOSE_WAIT:
                if(StreamTcpPacketStateCloseWait(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_LAST_ACK:
                if(StreamTcpPakcetStateLastAck(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_TIME_WAIT:
                if(StreamTcpPacketStateTimeWait(tv, p, stt, ssn))
                    SCReturnInt(-1);
                break;
            case TCP_CLOSED:
                SCLogDebug("packet received on closed state");
                break;
            default:
                SCLogDebug("packet received on default state");
                break;
        }

        if (ssn->state > TCP_ESTABLISHED) {
            p->flags |= PKT_STREAM_EOF;
        }
    }

    /* Process stream smsgs we may have in queue */
    if (StreamTcpReassembleProcessAppLayer(stt->ra_ctx) < 0)
        SCReturnInt(-1);

    SCReturnInt(0);
}

TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;
    TmEcode ret = TM_ECODE_OK;

    if (!(PKT_IS_TCP(p)))
        return TM_ECODE_OK;

    if (p->flow == NULL)
        return TM_ECODE_OK;

    SCMutexLock(&p->flow->m);
    ret = StreamTcpPacket(tv, p, stt);
    SCMutexUnlock(&p->flow->m);

    //if (ret)
      //  return TM_ECODE_FAILED;

    stt->pkts++;
    return TM_ECODE_OK;
}

TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    StreamTcpThread *stt = SCMalloc(sizeof(StreamTcpThread));
    if (stt == NULL)
        SCReturnInt(TM_ECODE_FAILED);
    memset(stt, 0, sizeof(StreamTcpThread));

    *data = (void *)stt;

    stt->counter_tcp_sessions = SCPerfTVRegisterCounter("tcp.sessions", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    stt->counter_tcp_ssn_memcap = SCPerfTVRegisterCounter("tcp.ssn_memcap_drop", tv,
                                                        SC_PERF_TYPE_UINT64,
                                                        "NULL");
    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);

    /* init reassembly ctx */
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx();
    if (stt->ra_ctx == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p",
                stt, stt->ra_ctx);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode StreamTcpThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return TM_ECODE_OK;
    }

    /* XXX */

    /* free reassembly ctx */
    StreamTcpReassembleFreeThreadCtx(stt->ra_ctx);

    /* clear memory */
    memset(stt, 0, sizeof(StreamTcpThread));

    SCFree(stt);
    SCReturnInt(TM_ECODE_OK);
}

void StreamTcpExitPrintStats(ThreadVars *tv, void *data)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return;
    }

    SCLogInfo("(%s) Packets %" PRIu64 "", tv->name, stt->pkts);
}

/**
 *  \brief   Function to check the validity of the RST packets based on the
 *           target OS of the given packet.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 */

static int ValidReset(TcpSession *ssn, Packet *p)
{

    uint8_t os_policy;

    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        if (!ValidTimestamp(ssn, p))
            return -1;
    }

    /* Set up the os_policy to be used in validating the RST packets based on
       target system */
    if (PKT_IS_TOSERVER(p)) {
        if (ssn->server.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->server, p);

        os_policy = ssn->server.os_policy;
    } else {
        if (ssn->client.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->server, p);

        os_policy = ssn->client.os_policy;
    }

    switch (os_policy) {
        case OS_POLICY_HPUX11:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not Valid! Packet SEQ: %" PRIu32 " "
                               "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " "
                               "and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->server.next_seq);
                    return 0;
                }
            }
            break;
        case OS_POLICY_OLD_LINUX:
        case OS_POLICY_LINUX:
        case OS_POLICY_SOLARIS:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len),
                            ssn->client.last_ack))
                { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p),
                              (ssn->client.next_seq + ssn->client.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                    TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ((TCP_GET_SEQ(p) + p->payload_len),
                            ssn->server.last_ack))
                { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p),
                                (ssn->server.next_seq + ssn->server.window)))
                    {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "",
                                    TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                 ssn->server.next_seq);
                    return 0;
                }
            }
            break;
        default:
        case OS_POLICY_BSD:
        case OS_POLICY_FIRST:
        case OS_POLICY_HPUX10:
        case OS_POLICY_IRIX:
        case OS_POLICY_MACOS:
        case OS_POLICY_LAST:
        case OS_POLICY_WINDOWS:
        case OS_POLICY_WINDOWS2K3:
        case OS_POLICY_VISTA:
            if(PKT_IS_TOSERVER(p)) {
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                               TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " "
                               "and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                               ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "",
                                TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " client SEQ: %" PRIu32 "", TCP_GET_SEQ(p),
                                 ssn->server.next_seq);
                    return 0;
                }
            }
            break;
    }
    return 0;
}

/**
 *  \brief  Function to return the FLOW state depending upon the TCP session state.
 *
 *  \param   s      TCP session of which the state has to be returned
 *  \retval  state  The FLOW_STATE_ depends upon the TCP sesison state, default is
 *                  FLOW_STATE_CLOSED
 */

int StreamTcpGetFlowState(void *s)
{
    SCEnter();

    TcpSession *ssn = (TcpSession *)s;
    if (ssn == NULL) {
        SCReturnInt(FLOW_STATE_CLOSED);
    }

    switch(ssn->state) {
        case TCP_NONE:
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
        case TCP_LISTEN:
            SCReturnInt(FLOW_STATE_NEW);

        case TCP_ESTABLISHED:
            SCReturnInt(FLOW_STATE_ESTABLISHED);

        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSED:
            SCReturnInt(FLOW_STATE_CLOSED);
    }

    SCReturnInt(FLOW_STATE_CLOSED);
}

/**
 *  \brief  Function to check the validity of the received timestamp based on
 *          the target OS of the given stream.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 *  \retval  If timestamp is valid, function returns 1 otherwise 0
 */

static int ValidTimestamp (TcpSession *ssn, Packet *p)
{
    SCEnter();

    TcpStream *sender_stream;
    TcpStream *receiver_stream;
    uint8_t ret = 1;
    uint8_t check_ts = 1;

    if (PKT_IS_TOSERVER(p)) {
        sender_stream = &ssn->client;
        receiver_stream = &ssn->server;
    } else {
        sender_stream = &ssn->server;
        receiver_stream = &ssn->client;
    }

    /* Set up the os_policy to be used in validating the timestamps based on
       the target system */
    if (receiver_stream->os_policy == 0)
        StreamTcpSetOSPolicy(receiver_stream, p);

    if (p->tcpvars.ts != NULL) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_FLAG_ZERO_TIMESTAMP) {
            /*The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    sender_stream->flags &= ~STREAMTCP_FLAG_ZERO_TIMESTAMP;
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        sender_stream->last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
                default:
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            /*HPUX11 igoners the timestamp of out of order packets*/
            if (!SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                check_ts = 0;
        }

        if (ts == 0) {
            switch (receiver_stream->os_policy) {
                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_WINDOWS2K3:
                case OS_POLICY_VISTA:
                case OS_POLICY_SOLARIS:
                    /*Old Linux and windows allowed packet with 0 timestamp.*/
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    SCReturnInt(0);
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, sender_stream->last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - sender_stream->last_ts) + 1);
            } else {
                result = (int32_t) (ts - sender_stream->last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (sender_stream->last_pkt_ts == 0 &&
                    (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid sender_stream->last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", sender_stream->last_ts, ts, result);
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                        (((uint32_t) p->ts.tv_sec) >
                            sender_stream->last_pkt_ts + PAWS_24DAYS))
            {
                SCLogDebug("packet is not valid sender_stream->last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                            sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);
                ret = 0;
            }

            if (ret == 1) {
                /* Update the timestamp and last seen packet time for this
                 * stream */
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                        && (((uint32_t) p->ts.tv_sec >
                                (sender_stream->last_pkt_ts + PAWS_24DAYS))))
                {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;
                    ret = 1;

                    SCLogDebug("timestamp considered valid anyway");
                }
            }
        }
    } else {
        /* Solaris stops using timestamps if a packet is received
           without a timestamp and timestamps were used on that stream. */
        if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
    }

    SCReturnInt(ret);
}

/** \brief  Set the No reassembly flag for the given direction in given TCP
 *          session.
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetSessionNoReassemblyFlag (TcpSession *ssn, char direction)
{
    direction ? (ssn->flags |= STREAMTCP_FLAG_NOSERVER_REASSEMBLY) :
                (ssn->flags |= STREAMTCP_FLAG_NOCLIENT_REASSEMBLY);
}

/** \brief  Set the No applayer inspection flag for the TCP session.
 *
 * \param ssn TCP Session to set the flag in
 */
void StreamTcpSetSessionNoApplayerInspectionFlag (TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_NO_APPLAYER_INSPECTION;
}

#ifdef UNITTESTS

/**
 *  \test   Test the allocation of TCP session for a given packet from the
 *          ssn_pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest01 (void) {
    Packet p;
    Flow f;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    TcpSession *ssn = StreamTcpNewSession(&p);
    if (ssn == NULL) {
        printf("Session can not be allocated: ");
        goto end;
    }
    f.protoctx = ssn;

    if (f.aldata != NULL) {
        printf("AppLayer field not set to NULL: ");
        goto end;
    }
    if (ssn->state != 0) {
        printf("TCP state field not set to 0: ");
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the deallocation of TCP session for a given packet and return
 *          the memory back to ssn_pool and corresponding segments to segment
 *          pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest02 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    StreamMsgQueue stream_q;
    memset(&stream_q, 0, sizeof(StreamMsgQueue));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    ra_ctx.stream_q = &stream_q;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(6);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN packet of the session. The session is setup only if midstream
 *          sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest03 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_SYN|TH_ACK;
    p.tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(19);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 20 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 11)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN/ACK packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest04 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK;
    p.tcph = &tcph;

    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(9);
    p.tcph->th_ack = htonl(19);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 10 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 20)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          3WHS packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest05 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(13);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(19);
    p.tcph->th_ack = htonl(16);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, 4); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 16 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we have seen only the
 *          FIN, RST packets packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest06 (void) {
    Packet p;
    Flow f;
    TcpSession ssn;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_flags = TH_FIN;
    p.tcph = &tcph;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx)) != NULL)
        goto end;

    p.tcph->th_flags = TH_RST;
    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx)) != NULL)
        goto end;

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the working on PAWS. The packet will be dropped by stream, as
 *          its timestamp is old, although the segment is in the window.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest07 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};
    TCPVars tcpvars;
    TCPOpt ts;
    uint32_t data[2];

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&tcpvars, 0, sizeof(TCPVars));
    memset(&ts, 0, sizeof(TCPOpt));

    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;

    data[0] = htonl(10);
    data[1] = htonl(11);

    ts.type = TCP_OPT_TS;
    ts.len = 10;
    ts.data = (uint8_t *)data;
    tcpvars.ts = &ts;
    p.tcpvars = tcpvars;

    p.payload = payload;
    p.payload_len = 1;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    data[0] = htonl(2);
    p.tcpc.ts1 = 0;
    p.tcpc.ts2 = 0;
    p.tcpvars.ts->data = (uint8_t *)data;

    if (StreamTcpPacket(&tv, &p, &stt) == -1) {
        if (((TcpSession *) (p.flow->protoctx))->client.next_seq != 11) {
            printf("the timestamp values are client %"PRIu32" server %" PRIu32""
                    " seq %" PRIu32 "\n", TCP_GET_TSVAL(&p), TCP_GET_TSECR(&p),
                    ((TcpSession *) (p.flow->protoctx))->client.next_seq);
            goto end;
        }

        StreamTcpSessionClear(p.flow->protoctx);
        ret = 1;
    }
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the working on PAWS. The packet will be accpeted by engine as
 *          the timestamp is valid and it is in window.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest08 (void) {

    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};
    TCPVars tcpvars;
    TCPOpt ts;
    uint32_t data[2];

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    memset(&tcpvars, 0, sizeof(TCPVars));
    memset(&ts, 0, sizeof(TCPOpt));

    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;

    data[0] = htonl(10);
    data[1] = htonl(11);

    ts.type = TCP_OPT_TS;
    ts.len = 10;
    ts.data = (uint8_t *)data;
    tcpvars.ts = &ts;
    p.tcpvars = tcpvars;

    p.payload = payload;
    p.payload_len = 1;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    data[0] = htonl(12);
    p.tcpc.ts1 = 0;
    p.tcpc.ts2 = 0;
    p.tcpvars.ts->data = (uint8_t *)data;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *) (p.flow->protoctx))->client.next_seq != 12) {
        printf("the timestamp values are client %"PRIu32" server %" PRIu32 " "
                "seq %" PRIu32 "\n", TCP_GET_TSVAL(&p), TCP_GET_TSECR(&p),
                ((TcpSession *) (p.flow->protoctx))->client.next_seq);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the working of No stream reassembly flag. The stream will not
 *          reassemble the segment if the flag is set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest09 (void) {

    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);
    stream_config.midstream = TRUE;

    //prevent L7 from kicking in
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;

    p.payload = payload;
    p.payload_len = 1;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(12);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpSetSessionNoReassemblyFlag(((TcpSession *)(p.flow->protoctx)), 0);

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *) (p.flow->protoctx))->client.seg_list->next == NULL)
        ret = 1;

    StreamTcpSessionClear(p.flow->protoctx);
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we see all the packets in that stream from start.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest10 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(6);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (! (((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p.flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN packet of that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest11 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN|TH_ACK;
    p.tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(2);
    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->server.last_ack != 2 &&
            ((TcpSession *)(p.flow->protoctx))->client.next_seq != 1) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p.flow->protoctx))->server.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest12 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p.tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(10);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(6);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p.flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *          Later, we start to receive the packet from other end stream too.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest13 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p.tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(10);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(6);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(9);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.last_ack != 9 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 14) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p.flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionPktFree(&p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/eidps\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "host-os-policy:\n"
    "\n"
    " windows: 192.168.0.1\n"
    "\n"
    " linux: 192.168.0.2\n"
    "\n";
/* Dummy conf string to setup the OS policy for unit testing */
static const char *dummy_conf_string1 =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/eidps\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "host-os-policy:\n"
    "\n"
    " windows: 192.168.0.0/24," "192.168.1.1\n"
    "\n"
    " linux: 192.168.1.0/24," "192.168.0.1\n"
    "\n";

/**
 *  \brief  Function to parse the dummy conf string and get the value of IP
 *          address for the corresponding OS policy type.
 *
 *  \param  conf_val_name   Name of the OS policy type
 *  \retval returns IP address as string on success and NULL on failure
 */
char *StreamTcpParseOSPolicy (char *conf_var_name)
{
    SCEnter();
    char conf_var_type_name[15] = "host-os-policy";
    char *conf_var_full_name = NULL;
    char *conf_var_value = NULL;

    if (conf_var_name == NULL)
        goto end;

    /* the + 2 is for the '.' and the string termination character '\0' */
    conf_var_full_name = (char *)SCMalloc(strlen(conf_var_type_name) +
                                        strlen(conf_var_name) + 2);
    if (conf_var_full_name == NULL)
        goto end;

    if (snprintf(conf_var_full_name,
                 strlen(conf_var_type_name) + strlen(conf_var_name) + 2, "%s.%s",
                 conf_var_type_name, conf_var_name) < 0) {
        SCLogError(SC_LOG_ERROR, "Error in making the conf full name");
        goto end;
    }

    if (ConfGet(conf_var_full_name, &conf_var_value) != 1) {
        SCLogError(SC_LOG_ERROR, "Error in getting conf value for conf name %s",
                    conf_var_full_name);
        goto end;
    }

    SCLogDebug("Value obtained from the yaml conf file, for the var "
               "\"%s\" is \"%s\"", conf_var_name, conf_var_value);

 end:
    if (conf_var_full_name != NULL)
        SCFree(conf_var_full_name);
    SCReturnCharPtr(conf_var_value);


}
/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest14 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;
    p.dst.family = AF_INET;
    p.dst.address.address_un_data32[0] = addr.s_addr;
    p.ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(14);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.0.2");
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p.flow->protoctx))->client.next_seq,
                ((TcpSession *)(p.flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p.flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p.flow->protoctx))->client.os_policy, OS_POLICY_WINDOWS,
                ((TcpSession *)(p.flow->protoctx))->server.os_policy,
                OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

/**
 *  \test   Test the setting up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest01 (void) {
    int ret = 0;
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = 0;
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if ((!(((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p.tcph->th_seq = htonl(10);
    p.tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p.tcph->th_flags = TH_SYN|TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(21);
    p.tcph->th_ack = htonl(10);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK, but the SYN/ACK does
 *          not have the right SEQ
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest02 (void) {
    int ret = 0;
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = 0;
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if ((!(((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p.tcph->th_seq = htonl(30);
    p.tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p.tcph->th_flags = TH_SYN|TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) != -1) {
        printf("SYN/ACK pkt not rejected but it should have: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK: however the SYN/ACK and ACK
 *          are part of a normal 3WHS
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest03 (void) {
    int ret = 0;
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    p.flow = &f;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = 0;
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if ((!(((TcpSession *)(p.flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p.tcph->th_seq = htonl(30);
    p.tcph->th_ack = htonl(11);
    p.tcph->th_flags = TH_SYN|TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(31);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest15 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.20");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;
    p.dst.family = AF_INET;
    p.dst.address.address_un_data32[0] = addr.s_addr;
    p.ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(14);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.20");
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p.flow->protoctx))->client.next_seq,
                ((TcpSession *)(p.flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p.flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p.flow->protoctx))->client.os_policy, OS_POLICY_WINDOWS,
                ((TcpSession *)(p.flow->protoctx))->server.os_policy,
                OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionPktFree(&p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest16 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;
    p.dst.family = AF_INET;
    p.dst.address.address_un_data32[0] = addr.s_addr;
    p.ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(14);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.1");
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p.flow->protoctx))->client.next_seq,
                ((TcpSession *)(p.flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p.flow->protoctx))->server.os_policy != OS_POLICY_WINDOWS)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p.flow->protoctx))->client.os_policy, OS_POLICY_LINUX,
                ((TcpSession *)(p.flow->protoctx))->server.os_policy,
                OS_POLICY_WINDOWS);
        goto end;
    }
    StreamTcpSessionPktFree(&p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1". To check the setting of
 *          Default os policy
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest17 (void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    char *ip_addr;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    p.flow = &f;
    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);
    strlcpy(os_policy_name, "linux\0", sizeof(os_policy_name));
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p.tcph = &tcph;
    p.dst.family = AF_INET;
    p.dst.address.address_un_data32[0] = addr.s_addr;
    p.ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(14);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    addr.s_addr = inet_addr("10.1.1.1");
    p.tcph->th_seq = htonl(25);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(24);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p.flow->protoctx))->client.next_seq,
                ((TcpSession *)(p.flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p.flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p.flow->protoctx))->server.os_policy != OS_POLICY_DEFAULT)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p.flow->protoctx))->client.os_policy, OS_POLICY_LINUX,
                ((TcpSession *)(p.flow->protoctx))->server.os_policy,
                OS_POLICY_DEFAULT);
        goto end;
    }
    StreamTcpSessionPktFree(&p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest18 (void) {

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet p;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&p, 0, sizeof(p));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p.dst.family = AF_INET;
    p.ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.1");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, &p);

    if (stream.os_policy != OS_POLICY_WINDOWS)
        goto end;

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest19 (void) {

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet p;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&p, 0, sizeof(p));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p.dst.family = AF_INET;
    p.ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.30");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, &p);

    if (stream.os_policy != OS_POLICY_WINDOWS) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8": ",
                OS_POLICY_WINDOWS, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest20 (void) {

    struct in_addr addr;
    char os_policy_name[10] = "linux";
    char *ip_addr;
    TcpStream stream;
    Packet p;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&p, 0, sizeof(p));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p.dst.family = AF_INET;
    p.ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.1");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, &p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest21 (void) {

    struct in_addr addr;
    char os_policy_name[10] = "linux";
    char *ip_addr;
    TcpStream stream;
    Packet p;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&p, 0, sizeof(p));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p.dst.family = AF_INET;
    p.ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.30");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, &p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest22 (void) {

    struct in_addr addr;
    char os_policy_name[10] = "windows";
    char *ip_addr;
    TcpStream stream;
    Packet p;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&p, 0, sizeof(p));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpInitConfig(TRUE);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p.dst.family = AF_INET;
    p.ip4h = &ipv4h;
    addr.s_addr = inet_addr("123.231.2.1");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, &p);

    if (stream.os_policy != OS_POLICY_DEFAULT) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                OS_POLICY_DEFAULT, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest23(void)
{
    TcpSession ssn;
    Packet p;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    uint8_t packet[1460] = "";
    int result = 1;

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.payload = packet;

    p.tcph->th_seq = htonl(3184324453UL);
    p.tcph->th_ack = htonl(3373419609UL);
    p.payload_len = 2;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p.tcph->th_seq = htonl(3184324455UL);
    p.tcph->th_ack = htonl(3373419621UL);
    p.payload_len = 2;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p.tcph->th_seq = htonl(3184324453UL);
    p.tcph->th_ack = htonl(3373419621UL);
    p.payload_len = 6;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if(ssn.client.seg_list_tail->payload_len != 4) {
        printf("failed in segment reassmebling\n");
        result &= 0;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    if (stream_memuse == 0) {
        result &= 1;
    } else {
        printf("stream_memuse %"PRIu32"\n", stream_memuse);
    }
    return result;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest24(void)
{
    TcpSession ssn;
    Packet p;
    Flow f;
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    uint8_t packet[1460] = "";
    int result = 1;

    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    memset(&ssn, 0, sizeof (TcpSession));
    memset(&p, 0, sizeof (Packet));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.payload = packet;

    p.tcph->th_seq = htonl(3184324455UL);
    p.tcph->th_ack = htonl(3373419621UL);
    p.payload_len = 4;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p.tcph->th_seq = htonl(3184324459UL);
    p.tcph->th_ack = htonl(3373419633UL);
    p.payload_len = 2;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    p.tcph->th_seq = htonl(3184324459UL);
    p.tcph->th_ack = htonl(3373419657UL);
    p.payload_len = 4;

    if (StreamTcpReassembleHandleSegment(ra_ctx,&ssn, &ssn.client, &p) == -1) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if(ssn.client.seg_list_tail->payload_len != 2) {
        printf("failed in segment reassmebling\n");
        result &= 0;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    if (stream_memuse == 0) {
        result &= 1;
    } else {
        printf("stream_memuse %"PRIu32"\n", stream_memuse);
    }
    return result;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest25(void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    int ret = 0;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    /* prevent L7 from kicking in */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOSERVER, 4096);
    StreamMsgQueueSetMinChunkLen(FLOW_PKT_TOCLIENT, 4096);

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(6);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest26(void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    int ret = 0;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_ECN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(6);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest27(void) {
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    int ret = 0;

    memset (&p, 0, sizeof(Packet));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(6);
    p.tcph->th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1 || (TcpSession *)p.flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

#endif /* UNITTESTS */

void StreamTcpRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpTest01 -- TCP session allocation",
                    StreamTcpTest01, 1);
    UtRegisterTest("StreamTcpTest02 -- TCP session deallocation",
                    StreamTcpTest02, 1);
    UtRegisterTest("StreamTcpTest03 -- SYN missed MidStream session",
                    StreamTcpTest03, 1);
    UtRegisterTest("StreamTcpTest04 -- SYN/ACK missed MidStream session",
                    StreamTcpTest04, 1);
    UtRegisterTest("StreamTcpTest05 -- 3WHS missed MidStream session",
                    StreamTcpTest05, 1);
    UtRegisterTest("StreamTcpTest06 -- FIN, RST message MidStream session",
                    StreamTcpTest06, 1);
    UtRegisterTest("StreamTcpTest07 -- PAWS invalid timestamp",
                    StreamTcpTest07, 1);
    UtRegisterTest("StreamTcpTest08 -- PAWS valid timestamp",
                    StreamTcpTest08, 1);
    UtRegisterTest("StreamTcpTest09 -- No Client Reassembly",
                    StreamTcpTest09, 1);
    UtRegisterTest("StreamTcpTest10 -- No missed packet Async stream",
                    StreamTcpTest10, 1);
    UtRegisterTest("StreamTcpTest11 -- SYN missed Async stream",
                    StreamTcpTest11, 1);
    UtRegisterTest("StreamTcpTest12 -- SYN/ACK missed Async stream",
                    StreamTcpTest12, 1);
    UtRegisterTest("StreamTcpTest13 -- opposite stream packets for Async "
                   "stream", StreamTcpTest13, 1);
    UtRegisterTest("StreamTcp4WHSTest01", StreamTcp4WHSTest01, 1);
    UtRegisterTest("StreamTcp4WHSTest02", StreamTcp4WHSTest02, 1);
    UtRegisterTest("StreamTcp4WHSTest03", StreamTcp4WHSTest03, 1);
    UtRegisterTest("StreamTcpTest14 -- setup OS policy", StreamTcpTest14, 1);
    UtRegisterTest("StreamTcpTest15 -- setup OS policy", StreamTcpTest15, 1);
    UtRegisterTest("StreamTcpTest16 -- setup OS policy", StreamTcpTest16, 1);
    UtRegisterTest("StreamTcpTest17 -- setup OS policy", StreamTcpTest17, 1);
    UtRegisterTest("StreamTcpTest18 -- setup OS policy", StreamTcpTest18, 1);
    UtRegisterTest("StreamTcpTest19 -- setup OS policy", StreamTcpTest19, 1);
    UtRegisterTest("StreamTcpTest20 -- setup OS policy", StreamTcpTest20, 1);
    UtRegisterTest("StreamTcpTest21 -- setup OS policy", StreamTcpTest21, 1);
    UtRegisterTest("StreamTcpTest22 -- setup OS policy", StreamTcpTest22, 1);
    UtRegisterTest("StreamTcpTest23 -- stream memory leaks", StreamTcpTest23, 1);
    UtRegisterTest("StreamTcpTest24 -- stream memory leaks", StreamTcpTest24, 1);
    UtRegisterTest("StreamTcpTest25 -- test ecn/cwr sessions",
                    StreamTcpTest25, 1);
    UtRegisterTest("StreamTcpTest26 -- test ecn/cwr sessions",
                    StreamTcpTest26, 1);
    UtRegisterTest("StreamTcpTest27 -- test ecn/cwr sessions",
                    StreamTcpTest27, 1);

    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();
#endif /* UNITTESTS */
}

