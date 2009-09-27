/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
/*  2009 Gurvinder Singh <gurvindersinghdahiya@gmail.com>*/

#include "eidps-common.h"
#include "decode.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "threads.h"

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

//#define DEBUG

typedef struct StreamTcpThread_ {
    uint64_t pkts;

    uint16_t counter_tcp_sessions;

    TcpReassemblyThreadCtx *ra_ctx;
} StreamTcpThread;

int StreamTcp (ThreadVars *, Packet *, void *, PacketQueue *);
int StreamTcpThreadInit(ThreadVars *, void *, void **);
int StreamTcpThreadDeinit(ThreadVars *, void *);
void StreamTcpExitPrintStats(ThreadVars *, void *);
static int ValidReset(TcpSession * , Packet *);
static int StreamTcpHandleFin(StreamTcpThread *, TcpSession *, Packet *);
void StreamTcpRegisterTests (void);
void StreamTcpReturnStreamSegments (TcpStream *);
void StreamTcpInitConfig(char);
extern void StreamTcpSegmentReturntoPool(TcpSegment *);
int StreamTcpGetFlowState(void *);
static int ValidTimestamp(TcpSession * , Packet *);

#define STREAMTCP_DEFAULT_SESSIONS      262144
#define STREAMTCP_DEFAULT_PREALLOC      32768

#define STREAMTCP_NEW_TIMEOUT           60
#define STREAMTCP_EST_TIMEOUT           3600
#define STREAMTCP_CLOSED_TIMEOUT        120

#define STREAMTCP_EMERG_NEW_TIMEOUT     10
#define STREAMTCP_EMERG_EST_TIMEOUT     300
#define STREAMTCP_EMERG_CLOSED_TIMEOUT  20

static Pool *ssn_pool = NULL;
static pthread_mutex_t ssn_pool_mutex;

#ifdef DEBUG
static uint64_t ssn_pool_cnt;
static pthread_mutex_t ssn_pool_cnt_mutex;
#endif

void TmModuleStreamTcpRegister (void) {
    tmm_modules[TMM_STREAMTCP].name = "StreamTcp";
    tmm_modules[TMM_STREAMTCP].ThreadInit = StreamTcpThreadInit;
    tmm_modules[TMM_STREAMTCP].Func = StreamTcp;
    tmm_modules[TMM_STREAMTCP].ThreadExitPrintStats = StreamTcpExitPrintStats;
    tmm_modules[TMM_STREAMTCP].ThreadDeinit = StreamTcpThreadDeinit;
    tmm_modules[TMM_STREAMTCP].RegisterTests = StreamTcpRegisterTests;
}

void StreamTcpReturnStreamSegments (TcpStream *stream) {
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
}

/** \brief Function to return the stream back to the pool. It returns the
 *         segments in the stream to the segment pool.
 *
 *  \param ssn Void ptr to the ssn.
 */
void StreamTcpSessionClear(void *ssnptr) {
    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        return;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    AppLayerParserCleanupState(ssn);

    memset(ssn, 0, sizeof(TcpSession));
    mutex_lock(&ssn_pool_mutex);
    PoolReturn(ssn_pool, ssn);
    mutex_unlock(&ssn_pool_mutex);

#ifdef DEBUG
    mutex_lock(&ssn_pool_cnt_mutex);
    ssn_pool_cnt--;
    mutex_unlock(&ssn_pool_cnt_mutex);
#endif
}

/** \brief Function to return the stream back to the pool. It returns the
 *         segments in the stream to the segment pool.
 *
 *  \param p Packet used to identify the stream.
 */
static void StreamTcpSessionPktFree (Packet *p) {
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL)
        return;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    AppLayerParserCleanupState(ssn);

    memset(ssn, 0, sizeof(TcpSession));
    mutex_lock(&ssn_pool_mutex);
    PoolReturn(ssn_pool, p->flow->protoctx);
    mutex_unlock(&ssn_pool_mutex);

    p->flow->protoctx = NULL;

#ifdef DEBUG
    mutex_lock(&ssn_pool_cnt_mutex);
    ssn_pool_cnt--;
    mutex_unlock(&ssn_pool_cnt_mutex);
#endif
}

/** \brief Stream alloc function for the Pool
 *  \param null NULL ptr (value of null is ignored)
 *  \retval ptr void ptr to TcpSession structure with all vars set to 0/NULL
 */
void *StreamTcpSessionPoolAlloc(void *null) {
    void *ptr = malloc(sizeof(TcpSession));
    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(TcpSession));
    return ptr;
}

/** \brief Pool free function
 *  \param s Void ptr to TcpSession memory */
void StreamTcpSessionPoolFree(void *s) {
    if (s == NULL)
        return;

    TcpSession *ssn = (TcpSession *)s;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    free(ssn);
}

/** \brief          To initialize the stream global configuration data
 *
 *  \param  quiet   It tells the mode of operation, if it is TRUE nothing will
 *                  be get printed.
 */

void StreamTcpInitConfig(char quiet) {

    //if (quiet == FALSE)
    //    printf("Initializing Stream:\n");

    memset(&stream_config,  0, sizeof(stream_config));

    /** set config defaults */
    stream_config.max_sessions = STREAMTCP_DEFAULT_SESSIONS;
    stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
    stream_config.midstream = TRUE;

    ssn_pool = PoolInit(stream_config.max_sessions, stream_config.prealloc_sessions, StreamTcpSessionPoolAlloc, NULL, StreamTcpSessionPoolFree);
    if (ssn_pool == NULL) {
        exit(1);
    }

    pthread_mutex_init(&ssn_pool_mutex, NULL);

    StreamTcpReassembleInit(quiet);

    /* set the default TCP timeout, free function and flow state function values. */
    FlowSetProtoTimeout(IPPROTO_TCP, STREAMTCP_NEW_TIMEOUT, STREAMTCP_EST_TIMEOUT, STREAMTCP_CLOSED_TIMEOUT);
    FlowSetProtoEmergencyTimeout(IPPROTO_TCP, STREAMTCP_EMERG_NEW_TIMEOUT, STREAMTCP_EMERG_EST_TIMEOUT, STREAMTCP_EMERG_CLOSED_TIMEOUT);

    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);
    FlowSetFlowStateFunc(IPPROTO_TCP, StreamTcpGetFlowState);
}

void StreamTcpFreeConfig(char quiet) {
    StreamTcpReassembleFree(quiet);

    if (ssn_pool != NULL) {
        PoolFree(ssn_pool);
        ssn_pool = NULL;
    } else {
        printf("ERROR: ssn_pool is NULL\n");
        exit(1);
    }
#ifdef DEBUG
    printf("ssn_pool_cnt %"PRIu64"\n", ssn_pool_cnt);
#endif
    pthread_mutex_destroy(&ssn_pool_mutex);
}

/** \brief The function is used to to fetch a TCP session from the
 *         ssn_pool, when a TCP SYN is received.
 *
 *  \param quiet Packet P, which has been recieved for the new TCP session.
 *
 *  \retval TcpSession A new TCP session with field initilaized to 0/NULL.
 */
TcpSession *StreamTcpNewSession (Packet *p) {
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        mutex_lock(&ssn_pool_mutex);
        p->flow->protoctx = PoolGet(ssn_pool);
        mutex_unlock(&ssn_pool_mutex);

        ssn = (TcpSession *)p->flow->protoctx;
        if (ssn == NULL)
            return NULL;

        ssn->state = TCP_NONE;
        ssn->aldata = NULL;

#ifdef DEBUG
        mutex_lock(&ssn_pool_cnt_mutex);
        ssn_pool_cnt++;
        mutex_unlock(&ssn_pool_cnt_mutex);
#endif
    }

    return ssn;
}

static inline void StreamTcpPacketSetState(Packet *p, TcpSession *ssn, uint8_t state) {
    if (state == ssn->state)
        return;

    ssn->state = state;

    FlowUpdateQueue(p->flow);
}

/**
 *  \brief  Function to handle the TCP_CLOSED or NONE state. The function handles
 *          packets while the session state is None which means a newly
 *          initialized structure, or a fully closed session.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    switch (p->tcph->th_flags) {
        case TH_SYN:
        {
            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL)
                    return -1;

                PerfCounterIncr(stt->counter_tcp_sessions, tv->pca);
            }

            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

            /* set the sequence numbers and window */
            ssn->client.isn = TCP_GET_SEQ(p);
            ssn->client.ra_base_seq = ssn->client.isn;
            ssn->client.next_seq = ssn->client.isn + 1;

            /*Set the stream timestamp value, if packet has timestamp option enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: p->tcpvars.ts %p, %02x", ssn, p->tcpvars.ts, ssn->client.last_ts);

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

            SCLogDebug("ssn %p: ssn->client.isn %" PRIu32 ", ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack %"PRIu32"",
                    ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack);
            break;
        }
        case TH_SYN|TH_ACK:
            if (stream_config.midstream == FALSE)
                break;

            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL)
                    return -1;
                PerfCounterIncr(stt->counter_tcp_sessions, tv->pca);
            }
            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now TCP_SYN_RECV", ssn);
            ssn->flags = STREAMTCP_FLAG_MIDSTREAM;

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

            SCLogDebug("ssn %p: ssn->client.isn %"PRIu32", ssn->client.next_seq %"PRIu32", ssn->client.last_ack %"PRIu32"",
                    ssn, ssn->client.isn, ssn->client.next_seq, ssn->client.last_ack);
            SCLogDebug("ssn %p: ssn->server.isn %"PRIu32", ssn->server.next_seq %"PRIu32", ssn->server.last_ack %"PRIu32"",
                    ssn, ssn->server.isn, ssn->server.next_seq, ssn->server.last_ack);

            /*Set the timestamp value for both streams, if packet has timestamp option enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                ssn->server.last_ts = TCP_GET_TSECR(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);

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
        /* Handle SYN/ACK and 3WHS shake missed together as it is almost similar. */
        case TH_ACK:
        case TH_ACK|TH_PUSH:
            if (stream_config.midstream == FALSE)
                break;
            if (ssn == NULL) {
                ssn = StreamTcpNewSession(p);
                if (ssn == NULL)
                    return -1;
                PerfCounterIncr(stt->counter_tcp_sessions, tv->pca);
            }
            /* set the state */
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now TCP_ESTABLISHED", ssn);

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

             SCLogDebug("ssn %p: ssn->client.next_win %"PRIu32", ssn->server.next_win %"PRIu32"",
                    ssn, ssn->client.next_win, ssn->server.next_win);
             SCLogDebug("ssn %p: ssn->client.last_ack %"PRIu32", ssn->server.last_ack %"PRIu32"",
                    ssn, ssn->client.last_ack, ssn->server.last_ack);

            /** window scaling for midstream pickups, we can't do much other
             *  than assume that it's set to the max value: 14 */
            ssn->client.wscale = TCP_WSCALE_MAX;
            ssn->server.wscale = TCP_WSCALE_MAX;

            /*Set the timestamp value for both streams, if packet has timestamp option enabled.*/
            if (p->tcpvars.ts != NULL) {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                ssn->server.last_ts = TCP_GET_TSECR(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);

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
        case TH_RST|TH_ACK|TH_PUSH:
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_PUSH:
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);
            break;
        case TH_SYN|TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
                return -1;
            }

            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != %" PRIu32 " from stream",
                        ssn, TCP_GET_ACK(p), ssn->client.isn + 1);
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

            if ((p->tcpvars.ts != NULL) && (ssn->client.flags & STREAMTCP_FLAG_TIMESTAMP)) {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" ssn->client.last_ts %" PRIu32"", ssn, ssn->server.last_ts, ssn->client.last_ts);
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
            if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE && p->tcpvars.ws != NULL) {
                ssn->client.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->client.wscale = 0;
            }

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 "", ssn, ssn->server.next_win);
            SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 "", ssn, ssn->client.next_win);
            SCLogDebug("ssn %p: ssn->server.isn %" PRIu32 ", ssn->server.next_seq %" PRIu32 ", ssn->server.last_ack %" PRIu32 " (ssn->client.last_ack %" PRIu32 ")",
                    ssn, ssn->server.isn, ssn->server.next_seq, ssn->server.last_ack, ssn->client.last_ack);
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)){
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) && SEQ_EQ(TCP_GET_WINDOW(p), 0) && SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1))) {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);
            break;
        case TH_SYN|TH_ACK:
            SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV... resent", ssn);
            break;
        case TH_ACK:
            /* If the timestamp option is enabled for both the streams, then validate the received packet
               timestamp value against the stream->last_ts. If the timestamp is valid then process the packet normally
               otherwise the drop the packet (RFC 1323)*/
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: ACK received in the wrong direction", ssn);
                return -1;
            }

            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
                SCLogDebug("ssn %p: wrong seq nr on packet", ssn);
                return -1;
            }
            ssn->server.last_ack = TCP_GET_ACK(p);

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                /** window scaling for midstream pickups, we can't do much other
                 *  than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
            }
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                    ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            ssn->client.next_seq += p->payload_len;
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", ssn->server.last_ack %"PRIu32"", ssn, ssn->server.next_win, ssn->server.last_ack);
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
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
 *  \brief  Function to handle the TCP_ESTABLISHED state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state. The function handles the data inside packets and call
 *          StreamTcpReassembleHandleSegment() to handle the reassembling.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            SCLogDebug("ssn %p: SYN packet on state ESTABLISED... resent", ssn);
            break;
        case TH_SYN|TH_ACK:
            SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent", ssn);
            break;
        case TH_ACK:
        case TH_ACK|TH_PUSH:
            /* If the timestamp option is enabled for both the streams, then validate the received packet
               timestamp value against the stream->last_ts. If the timestamp is valid then process the packet normally
               otherwise the drop the packet (RFC 1323) */
            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 ", WIN %"PRIu16"",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    ssn->client.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "", ssn, ssn->client.next_seq);
                }

                if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.last_ack)) {
                    if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
                        ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win %" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
                        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn, ssn->server.window);

                        if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                            ssn->server.last_ack = TCP_GET_ACK(p);

                        if (SEQ_GT((ssn->server.last_ack + ssn->server.window), ssn->server.next_win)) {
                            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                            SCLogDebug("ssn %p: seq %"PRIu32", updated ssn->server.next_win %" PRIu32 " (win %"PRIu32")", ssn, TCP_GET_SEQ(p), ssn->server.next_win, ssn->server.window);
                        }

                        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                    } else {
                        SCLogDebug("ssn %p: server => SEQ out of window, packet SEQ %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), ssn->client.last_ack %" PRIu32 ", ssn->client.next_win %" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win, ssn->client.ra_base_seq);
                    }
                } else {
                    SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), ssn->client.last_ack %" PRIu32 ", ssn->client.next_win %" PRIu32 "(%"PRIu32") (ssn->client.ra_base_seq %"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win, ssn->client.ra_base_seq);
                }

                SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ", next win %" PRIu32 ", win %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack, ssn->client.next_win, ssn->client.window);
            } else { /* implied to client */
                SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 ", WIN %"PRIu16"",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

                /* To get the server window value from the servers packet, when connection
                   is picked up as midstream */
                if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED)) {
                    ssn->server.window = TCP_GET_WINDOW(p);
                    ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                    ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
                    SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to %" PRIu32 "", ssn, ssn->server.next_win);
                }

                if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                    ssn->server.next_seq += p->payload_len;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
                }

                if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.last_ack)) {
                    if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
                        ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win %" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
                        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn, ssn->client.window);

                        if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                            ssn->client.last_ack = TCP_GET_ACK(p);

                        if (SEQ_GT((ssn->client.last_ack + ssn->client.window), ssn->client.next_win)) {
                            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                            SCLogDebug("ssn %p: seq %"PRIu32", updated ssn->client.next_win %" PRIu32 " (win %"PRIu32")", ssn, TCP_GET_SEQ(p), ssn->client.next_win, ssn->client.window);
                        } else {
                            SCLogDebug("ssn %p: seq %"PRIu32", keeping ssn->client.next_win %" PRIu32 " the same (win %"PRIu32")", ssn, TCP_GET_SEQ(p), ssn->client.next_win, ssn->client.window);
                        }

                        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                    } else {
                        SCLogDebug("ssn %p: client => SEQ out of window, packet SEQ %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), ssn->server.last_ack %" PRIu32 ", ssn->server.next_win %" PRIu32 "(%"PRIu32") (ssn->server.ra_base_seq %"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->server.last_ack, ssn->server.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win, ssn->server.ra_base_seq);
                    }
                } else {
                    SCLogDebug("ssn %p: client => SEQ before last ack, packet SEQ %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), ssn->server.last_ack %" PRIu32 ", ssn->server.next_win %" PRIu32 "(%"PRIu32") (ssn->server.ra_base_seq %"PRIu32")", ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->server.last_ack, ssn->server.next_win, TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win, ssn->server.ra_base_seq);
                }
                SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ", next win %" PRIu32 ", win %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack, ssn->server.next_win, ssn->server.window);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_PUSH:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            SCLogDebug("StreamTcpPacketStateEstablished (%p): FIN received SEQ %" PRIu32 ", last ACK %" PRIu32 ", next win %" PRIu32 ", win %" PRIu32 "",
                    ssn, ssn->server.next_seq, ssn->client.last_ack, ssn->server.next_win, ssn->server.window);

            if((StreamTcpHandleFin(stt, ssn, p)) == -1)
                return -1;
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                if(PKT_IS_TOSERVER(p)) {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: Reset received and state changed to TCP_CLOSED", ssn);

                    ssn->client.next_seq = TCP_GET_ACK(p);
                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
                    ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                        ssn->server.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                    SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                            ssn, ssn->client.next_seq, ssn->server.last_ack);
                } else {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: Reset received and state changed to TCP_CLOSED", ssn);

                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    ssn->client.next_seq = TCP_GET_ACK(p);

                    SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
                    ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                        ssn->client.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                    SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                            ssn, ssn->server.next_seq, ssn->client.last_ack);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpHandleFin(StreamTcpThread *stt, TcpSession *ssn, Packet *p) {

    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window))) {
              SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                      ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
              return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        ssn->client.next_seq = TCP_GET_ACK(p);
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
            ssn->server.last_ack = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { /* implied to client */
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));
        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                    ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        ssn->client.next_seq = TCP_GET_ACK(p);
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn, ssn->server.next_seq);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_ACK:

           if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));
                StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_PUSH:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED", ssn);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait2(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch (p->tcph->th_flags) {
        case TH_ACK:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: Reset received state changed to TCP_CLOSED", ssn);
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
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);

                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateClosing(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("StreamTcpPacketStateClosing (%p): =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateCloseWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_FIN:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOCLIENT(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_LAST_ACK state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool. The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPakcetStateLastAck(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
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
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateTimeWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt, TcpSession *ssn) {
    if (ssn == NULL)
        return -1;

    switch(p->tcph->th_flags) {
        case TH_ACK:

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                if (!ValidTimestamp(ssn, p))
                    return -1;
            }

            if (PKT_IS_TOSERVER(p)) {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->client, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else {
                SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", ACK %" PRIu32 "",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != %" PRIu32 " from stream",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(stt->ra_ctx, ssn, &ssn->server, p);
                SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            SCLogDebug("ssn %p: default case", ssn);
            break;

    }
    return 0;
}

/* flow is and stays locked */
static int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone(tv, p, stt, ssn) == -1)
            return -1;
    } else {
        switch (ssn->state) {
            case TCP_SYN_SENT:
                if(StreamTcpPacketStateSynSent(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_SYN_RECV:
                if(StreamTcpPacketStateSynRecv(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_ESTABLISHED:
                if(StreamTcpPacketStateEstablished(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_FIN_WAIT1:
                if(StreamTcpPacketStateFinWait1(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_FIN_WAIT2:
                if(StreamTcpPacketStateFinWait2(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_CLOSING:
                if(StreamTcpPacketStateClosing(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_CLOSE_WAIT:
                if(StreamTcpPacketStateCloseWait(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_LAST_ACK:
                if(StreamTcpPakcetStateLastAck(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_TIME_WAIT:
                if(StreamTcpPacketStateTimeWait(tv, p, stt, ssn))
                    return -1;
                break;
            case TCP_CLOSED:
                //printf("StreamTcpPacket: packet received on closed state\n");
                break;
            default:
                //printf("StreamTcpPacket: packet received on default state\n");
                break;
        }
    }

    /* Process stream smsgs we may have in queue */
    StreamTcpReassembleProcessAppLayer(stt->ra_ctx);
    return 0;
}

int StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;

    if (!(PKT_IS_TCP(p)))
        return 0;

    if (p->flow == NULL)
        return 0;

    mutex_lock(&p->flow->m);
    StreamTcpPacket(tv, p, stt);
    mutex_unlock(&p->flow->m);

    stt->pkts++;
    return 0;
}

int StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
    if (stt == NULL) {
        return -1;
    }
    memset(stt, 0, sizeof(StreamTcpThread));

    *data = (void *)stt;

    stt->counter_tcp_sessions = PerfTVRegisterCounter("tcp.sessions", tv, TYPE_UINT64, "NULL");
    tv->pca = PerfGetAllCountersArray(&tv->pctx);
    PerfAddToClubbedTMTable(tv->name, &tv->pctx);

    /* init reassembly ctx */
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx();
    if (stt->ra_ctx == NULL)
        return -1;

    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p", stt, stt->ra_ctx);
    return 0;
}

int StreamTcpThreadDeinit(ThreadVars *tv, void *data)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return 0;
    }

    /* XXX */

    /* free reassembly ctx */


    /* clear memory */
    memset(stt, 0, sizeof(StreamTcpThread));

    free(stt);
    return 0;
}

void StreamTcpExitPrintStats(ThreadVars *tv, void *data) {
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return;
    }

    printf(" - (%s) Packets %" PRIu64 ".\n", tv->name, stt->pkts);
}

/**
 *  \brief   Function to check the validity of the RST packets based on the target
 *          OS of the given packet.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 */

static int ValidReset(TcpSession *ssn, Packet *p) {

    uint8_t os_policy;

    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        if (!ValidTimestamp(ssn, p))
            return -1;
    }

    if (PKT_IS_TOSERVER(p))
        os_policy = ssn->server.os_policy;
    else
        os_policy = ssn->client.os_policy;

    switch (os_policy) {
        case OS_POLICY_HPUX11:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not Valid! Packet SEQ: %" PRIu32 " and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);
                    return 0;
                }
            }
            break;
        case OS_POLICY_OLD_LINUX:
        case OS_POLICY_LINUX:
        case OS_POLICY_SOLARIS:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack)) { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->client.next_seq + ssn->client.window))) {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack)) { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->server.next_seq + ssn->server.window))) {
                        SCLogDebug("reset is Valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);
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
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and server SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->client.next_seq);
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 "", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and client SEQ: %" PRIu32 "", TCP_GET_SEQ(p), ssn->server.next_seq);
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
 *  \param   s    TCP session of which the state has to be returned
 *  \retval  The FLOW_STATE_ depends upon the TCP sesison state, default is FLOW_STATE_CLOSED
 */

int StreamTcpGetFlowState(void *s) {
    TcpSession *ssn = (TcpSession *)s;
    if (ssn == NULL)
        return FLOW_STATE_CLOSED;

    switch(ssn->state) {
        case TCP_NONE:
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
        case TCP_LISTEN:
            return FLOW_STATE_NEW;
        case TCP_ESTABLISHED:
            return FLOW_STATE_ESTABLISHED;
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSE_WAIT:
        case TCP_CLOSED:
            return FLOW_STATE_CLOSED;
    }
    return FLOW_STATE_CLOSED;
}

/**
 *  \brief  Function to check the validity of the received timestamp based on the target
 *          OS of the given stream.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 *  \retval  If timestamp is valid, function returns 1 otherwise 0
 */

static int ValidTimestamp (TcpSession *ssn, Packet *p) {

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

    if (p->tcpvars.ts != NULL) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_FLAG_ZERO_TIMESTAMP) {
            /*The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /*Linux and windows 2003 does not allow the use of 0 as timestamp
                      in the 3whs. */
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
                                        and stream TS has been updated with this one.*/
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
                    /* other OS simply drop the pakcet with 0 timestamp, when 3whs
                       has valid timestamp*/
                    return 0;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            if (receiver_stream->os_policy == OS_POLICY_LINUX) {
                result = (int32_t) ((ts - sender_stream->last_ts) + 1); /* Linux accepts TS which are off by one.*/
            } else {
                result = (int32_t) (ts - sender_stream->last_ts);
            }

            if (sender_stream->last_pkt_ts == 0 && (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
                sender_stream->last_pkt_ts = p->ts.tv_sec;

            if (result < 0) {
                SCLogDebug("timestamp is not valid sender_stream->last_ts %" PRIu32 " p->tcpvars->ts %" PRIu32 " result %" PRId32 "", sender_stream->last_ts, ts, result);
                ret = 0;
            } else if ((sender_stream->last_ts != 0) && (((uint32_t) p->ts.tv_sec) > sender_stream->last_pkt_ts + PAWS_24DAYS)) {
                SCLogDebug("packet is not valid sender_stream->last_pkt_ts %" PRIu32 " p->ts.tv_sec %" PRIu32 "", sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);
                ret = 0;
            }

            if (ret == 1) {
                /*Update the timestamp and last seen packet time for this stream.*/
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;
                sender_stream->last_pkt_ts = p->ts.tv_sec;
            }

            if (ret == 0) {
                /*if the timestamp of packet is not valid then, check if the current
                  stream timestamp is not so old. if so then we need to accept the packet
                  and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                        && (((uint32_t) p->ts.tv_sec > (sender_stream->last_pkt_ts + PAWS_24DAYS)))) {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;
                    ret = 1;
                }
            }
        }
    } else {
        /* Solaris stops using timestamps if a packet is received
           without a timestamp and timestamps were used on that stream. */
        if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
    }

    return ret;
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
        printf("Session can not be allocated \n");
        goto end;
    }
    f.protoctx = ssn;

    if (ssn->aldata != NULL) {
        printf("AppLayer field not set to NULL \n");
        goto end;
    }
    if (ssn->state != 0) {
        printf("TCP state field not set to 0 \n");
        goto end;
    }

    StreamTcpSessionPktFree(&p);

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
    u_int8_t payload[4];
    TCPHdr tcph;
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

    StreamTcpCreateTestPacket(payload, 0x41, 3); /*AAA*/
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

    StreamTcpCreateTestPacket(payload, 0x42, 3); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    StreamTcpSessionPktFree(&p);
    if (p.flow->protoctx != NULL)
        goto end;

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

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 20 ||
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 11)
        goto end;

    StreamTcpSessionPktFree(&p);

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

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 10 ||
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 20)
        goto end;

    StreamTcpSessionPktFree(&p);

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
    u_int8_t payload[4];
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

    StreamTcpCreateTestPacket(payload, 0x41, 3); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(20);
    p.tcph->th_ack = htonl(13);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3); /*BBB*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(13);
    p.tcph->th_ack = htonl(23);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3); /*CCC*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt) == -1)
        goto end;

    p.tcph->th_seq = htonl(19);
    p.tcph->th_ack = htonl(16);
    p.tcph->th_flags = TH_ACK|TH_PUSH;
    p.flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3); /*DDD*/
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

    if (((TcpSession *)(p.flow->protoctx))->client.next_seq != 16 ||
            ((TcpSession *)(p.flow->protoctx))->server.next_seq != 23)
        goto end;

    StreamTcpSessionPktFree(&p);

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
    u_int8_t payload[1] = {0x42};
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
            printf("the timestamp values are client %"PRIu32" server %" PRIu32 " seq %" PRIu32 "\n", TCP_GET_TSVAL(&p), TCP_GET_TSECR(&p), ((TcpSession *) (p.flow->protoctx))->client.next_seq);
            goto end;
        }

        StreamTcpSessionPktFree(&p);
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
    u_int8_t payload[1] = {0x42};
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
        printf("the timestamp values are client %"PRIu32" server %" PRIu32 " seq %" PRIu32 "\n", TCP_GET_TSVAL(&p), TCP_GET_TSECR(&p), ((TcpSession *) (p.flow->protoctx))->client.next_seq);
        goto end;
    }

    StreamTcpSessionPktFree(&p);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

#endif /* UNITTESTS */

void StreamTcpRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpTest01 -- TCP session allocation", StreamTcpTest01, 1);
    UtRegisterTest("StreamTcpTest02 -- TCP session deallocation", StreamTcpTest02, 1);
    UtRegisterTest("StreamTcpTest03 -- SYN missed MidStream session", StreamTcpTest03, 1);
    UtRegisterTest("StreamTcpTest04 -- SYN/ACK missed MidStream session", StreamTcpTest04, 1);
    UtRegisterTest("StreamTcpTest05 -- 3WHS missed MidStream session", StreamTcpTest05, 1);
    UtRegisterTest("StreamTcpTest06 -- FIN, RST message MidStream session", StreamTcpTest06, 1);
    UtRegisterTest("StreamTcpTest07 -- PAWS invalid timestamp", StreamTcpTest07, 1);
    UtRegisterTest("StreamTcpTest08 -- PAWS valid timestamp", StreamTcpTest08, 1);
    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();
#endif /* UNITTESTS */
}

