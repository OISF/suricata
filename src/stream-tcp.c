/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * TCP stream tracking and reassembly engine.
 *
 * \todo - 4WHS: what if after the 2nd SYN we turn out to be normal 3WHS anyway?
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "debug.h"
#include "detect.h"

#include "flow.h"
#include "flow-util.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-pool.h"
#include "util-pool-thread.h"
#include "util-checksum.h"
#include "util-unittest.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-device.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-sack.h"
#include "stream-tcp-util.h"
#include "stream.h"

#include "pkt-var.h"
#include "host.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp-mem.h"

#include "util-host-os-info.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-misc.h"
#include "util-validate.h"
#include "util-runmodes.h"
#include "util-random.h"
#include "util-exception-policy.h"

#include "source-pcap-file.h"

//#define DEBUG

#define STREAMTCP_DEFAULT_PREALLOC              2048
#define STREAMTCP_DEFAULT_MEMCAP                (64 * 1024 * 1024)  /* 64mb */
#define STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP     (256 * 1024 * 1024) /* 256mb */
#define STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE   2560
#define STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED     5

#define STREAMTCP_NEW_TIMEOUT                   60
#define STREAMTCP_EST_TIMEOUT                   3600
#define STREAMTCP_CLOSED_TIMEOUT                120

#define STREAMTCP_EMERG_NEW_TIMEOUT             10
#define STREAMTCP_EMERG_EST_TIMEOUT             300
#define STREAMTCP_EMERG_CLOSED_TIMEOUT          20

static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *, TcpSession *, Packet *, PacketQueueNoLock *);
void StreamTcpReturnStreamSegments (TcpStream *);
void StreamTcpInitConfig(char);
int StreamTcpGetFlowState(void *);
void StreamTcpSetOSPolicy(TcpStream*, Packet*);

static int StreamTcpValidateTimestamp(TcpSession * , Packet *);
static int StreamTcpHandleTimestamp(TcpSession * , Packet *);
static int StreamTcpValidateRst(TcpSession * , Packet *);
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *, Packet *);
static int StreamTcpStateDispatch(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq,
        uint8_t state);
#ifdef DEBUG
extern thread_local uint64_t t_pcapcnt;
#endif
extern int g_detect_disabled;

static PoolThread *ssn_pool = NULL;
static SCMutex ssn_pool_mutex = SCMUTEX_INITIALIZER; /**< init only, protect initializing and growing pool */
#ifdef DEBUG
static uint64_t ssn_pool_cnt = 0; /** counts ssns, protected by ssn_pool_mutex */
#endif

TcpStreamCnf stream_config;
uint64_t StreamTcpReassembleMemuseGlobalCounter(void);
SC_ATOMIC_DECLARE(uint64_t, st_memuse);

void StreamTcpInitMemuse(void)
{
    SC_ATOMIC_INIT(st_memuse);
}

void StreamTcpIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(st_memuse, size);
    SCLogDebug("STREAM %"PRIu64", incr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

void StreamTcpDecrMemuse(uint64_t size)
{
#if defined(DEBUG_VALIDATION) && defined(UNITTESTS)
    uint64_t presize = SC_ATOMIC_GET(st_memuse);
    if (RunmodeIsUnittests()) {
        BUG_ON(presize > UINT_MAX);
    }
#endif

    (void) SC_ATOMIC_SUB(st_memuse, size);

#if defined(DEBUG_VALIDATION) && defined(UNITTESTS)
    if (RunmodeIsUnittests()) {
        uint64_t postsize = SC_ATOMIC_GET(st_memuse);
        BUG_ON(postsize > presize);
    }
#endif
    SCLogDebug("STREAM %"PRIu64", decr %"PRIu64, StreamTcpMemuseCounter(), size);
    return;
}

uint64_t StreamTcpMemuseCounter(void)
{
    uint64_t memusecopy = SC_ATOMIC_GET(st_memuse);
    return memusecopy;
}

/**
 *  \brief Check if alloc'ing "size" would mean we're over memcap
 *
 *  \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
int StreamTcpCheckMemcap(uint64_t size)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.memcap);
    if (memcapcopy == 0 || size + SC_ATOMIC_GET(st_memuse) <= memcapcopy)
        return 1;
    return 0;
}

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int StreamTcpSetMemcap(uint64_t size)
{
    if (size == 0 || (uint64_t)SC_ATOMIC_GET(st_memuse) < size) {
        SC_ATOMIC_SET(stream_config.memcap, size);
        return 1;
    }

    return 0;
}

/**
 *  \brief Return memcap value
 *
 *  \param memcap memcap value
 */
uint64_t StreamTcpGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(stream_config.memcap);
    return memcapcopy;
}

void StreamTcpStreamCleanup(TcpStream *stream)
{
    if (stream != NULL) {
        StreamTcpSackFreeList(stream);
        StreamTcpReturnStreamSegments(stream);
        StreamingBufferClear(&stream->sb);
    }
}

static void StreamTcp3wsFreeQueue(TcpSession *ssn)
{
    TcpStateQueue *q, *q_next;
    q = ssn->queue;
    while (q != NULL) {
        q_next = q->next;
        SCFree(q);
        q = q_next;
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpStateQueue));
    }
    ssn->queue = NULL;
    ssn->queue_len = 0;
}

/**
 *  \brief Session cleanup function. Does not free the ssn.
 *  \param ssn tcp session
 */
void StreamTcpSessionCleanup(TcpSession *ssn)
{
    SCEnter();

    if (ssn == NULL)
        return;

    StreamTcpStreamCleanup(&ssn->client);
    StreamTcpStreamCleanup(&ssn->server);
    StreamTcp3wsFreeQueue(ssn);

    SCReturn;
}

/**
 *  \brief Function to return the stream back to the pool. It returns the
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
    TcpSession *ssn = (TcpSession *)ssnptr;
    if (ssn == NULL)
        return;

    StreamTcpSessionCleanup(ssn);

    /* HACK: don't loose track of thread id */
    PoolThreadReserved a = ssn->res;
    memset(ssn, 0, sizeof(TcpSession));
    ssn->res = a;

    PoolThreadReturn(ssn_pool, ssn);
#ifdef DEBUG
    SCMutexLock(&ssn_pool_mutex);
    ssn_pool_cnt--;
    SCMutexUnlock(&ssn_pool_mutex);
#endif

    SCReturn;
}

/**
 *  \brief Function to return the stream segments back to the pool.
 *
 *  We don't clear out the app layer storage here as that is under protection
 *  of the "use_cnt" reference counter in the flow. This function is called
 *  when the use_cnt is always at least 1 (this pkt has incremented the flow
 *  use_cnt itself), so we don't bother.
 *
 *  \param p Packet used to identify the stream.
 */
void StreamTcpSessionPktFree (Packet *p)
{
    SCEnter();

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL)
        SCReturn;

    StreamTcpReturnStreamSegments(&ssn->client);
    StreamTcpReturnStreamSegments(&ssn->server);

    SCReturn;
}

/** \brief Stream alloc function for the Pool
 *  \retval ptr void ptr to TcpSession structure with all vars set to 0/NULL
 */
static void *StreamTcpSessionPoolAlloc(void)
{
    void *ptr = NULL;

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpSession)) == 0)
        return NULL;

    ptr = SCMalloc(sizeof(TcpSession));
    if (unlikely(ptr == NULL))
        return NULL;

    return ptr;
}

static int StreamTcpSessionPoolInit(void *data, void* initdata)
{
    memset(data, 0, sizeof(TcpSession));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpSession));

    return 1;
}

/** \brief Pool cleanup function
 *  \param s Void ptr to TcpSession memory */
static void StreamTcpSessionPoolCleanup(void *s)
{
    if (s != NULL) {
        StreamTcpSessionCleanup(s);
        /** \todo not very clean, as the memory is not freed here */
        StreamTcpDecrMemuse((uint64_t)sizeof(TcpSession));
    }
}

/**
 *  \brief See if stream engine is dropping invalid packet in inline mode
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int StreamTcpInlineDropInvalid(void)
{
    return ((stream_config.flags & STREAMTCP_INIT_FLAG_INLINE)
            && (stream_config.flags & STREAMTCP_INIT_FLAG_DROP_INVALID));
}

/* hack: stream random range code expects random values in range of 0-RAND_MAX,
 * but we can get both <0 and >RAND_MAX values from RandomGet
 */
static int RandomGetWrap(void)
{
    unsigned long r;

    do {
        r = RandomGet();
    } while(r >= ULONG_MAX - (ULONG_MAX % RAND_MAX));

    return r % RAND_MAX;
}

/** \brief          To initialize the stream global configuration data
 *
 *  \param  quiet   It tells the mode of operation, if it is TRUE nothing will
 *                  be get printed.
 */

void StreamTcpInitConfig(char quiet)
{
    intmax_t value = 0;
    uint16_t rdrange = 10;

    SCLogDebug("Initializing Stream");

    memset(&stream_config,  0, sizeof(stream_config));

    SC_ATOMIC_INIT(stream_config.memcap);
    SC_ATOMIC_INIT(stream_config.reassembly_memcap);

    if ((ConfGetInt("stream.max-sessions", &value)) == 1) {
        SCLogWarning(SC_WARN_OPTION_OBSOLETE, "max-sessions is obsolete. "
            "Number of concurrent sessions is now only limited by Flow and "
            "TCP stream engine memcaps.");
    }

    if ((ConfGetInt("stream.prealloc-sessions", &value)) == 1) {
        stream_config.prealloc_sessions = (uint32_t)value;
    } else {
        if (RunmodeIsUnittests()) {
            stream_config.prealloc_sessions = 128;
        } else {
            stream_config.prealloc_sessions = STREAMTCP_DEFAULT_PREALLOC;
            if (ConfGetNode("stream.prealloc-sessions") != NULL) {
                WarnInvalidConfEntry("stream.prealloc_sessions",
                                     "%"PRIu32,
                                     stream_config.prealloc_sessions);
            }
        }
    }
    if (!quiet) {
        SCLogConfig("stream \"prealloc-sessions\": %"PRIu32" (per thread)",
                stream_config.prealloc_sessions);
    }

    const char *temp_stream_memcap_str;
    if (ConfGetValue("stream.memcap", &temp_stream_memcap_str) == 1) {
        uint64_t stream_memcap_copy;
        if (ParseSizeStringU64(temp_stream_memcap_str, &stream_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing stream.memcap "
                       "from conf file - %s.  Killing engine",
                       temp_stream_memcap_str);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.memcap, stream_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.memcap, STREAMTCP_DEFAULT_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream \"memcap\": %"PRIu64, SC_ATOMIC_GET(stream_config.memcap));
    }

    ConfGetBool("stream.midstream", &stream_config.midstream);

    if (!quiet) {
        SCLogConfig("stream \"midstream\" session pickups: %s", stream_config.midstream ? "enabled" : "disabled");
    }

    ConfGetBool("stream.async-oneside", &stream_config.async_oneside);

    if (!quiet) {
        SCLogConfig("stream \"async-oneside\": %s", stream_config.async_oneside ? "enabled" : "disabled");
    }

    int csum = 0;

    if ((ConfGetBool("stream.checksum-validation", &csum)) == 1) {
        if (csum == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
        }
    /* Default is that we validate the checksum of all the packets */
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION;
    }

    if (!quiet) {
        SCLogConfig("stream \"checksum-validation\": %s",
                stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION ?
                "enabled" : "disabled");
    }

    const char *temp_stream_inline_str;
    if (ConfGetValue("stream.inline", &temp_stream_inline_str) == 1) {
        int inl = 0;

        /* checking for "auto" and falling back to boolean to provide
         * backward compatibility */
        if (strcmp(temp_stream_inline_str, "auto") == 0) {
            if (EngineModeIsIPS()) {
                stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
            }
        } else if (ConfGetBool("stream.inline", &inl) == 1) {
            if (inl) {
                stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
            }
        }
    } else {
        /* default to 'auto' */
        if (EngineModeIsIPS()) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_INLINE;
        }
    }
    stream_config.ssn_memcap_policy = ExceptionPolicyParse("stream.memcap-policy", true);
    stream_config.reassembly_memcap_policy =
            ExceptionPolicyParse("stream.reassembly.memcap-policy", true);
    stream_config.midstream_policy = ExceptionPolicyMidstreamParse(stream_config.midstream);

    if (!quiet) {
        SCLogConfig("stream.\"inline\": %s",
                    stream_config.flags & STREAMTCP_INIT_FLAG_INLINE
                    ? "enabled" : "disabled");
    }

    int bypass = 0;
    if ((ConfGetBool("stream.bypass", &bypass)) == 1) {
        if (bypass == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_BYPASS;
        }
    }

    if (!quiet) {
        SCLogConfig("stream \"bypass\": %s",
                    (stream_config.flags & STREAMTCP_INIT_FLAG_BYPASS)
                    ? "enabled" : "disabled");
    }

    int drop_invalid = 0;
    if ((ConfGetBool("stream.drop-invalid", &drop_invalid)) == 1) {
        if (drop_invalid == 1) {
            stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
        }
    } else {
        stream_config.flags |= STREAMTCP_INIT_FLAG_DROP_INVALID;
    }

    if ((ConfGetInt("stream.max-synack-queued", &value)) == 1) {
        if (value >= 0 && value <= 255) {
            stream_config.max_synack_queued = (uint8_t)value;
        } else {
            stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
        }
    } else {
        stream_config.max_synack_queued = (uint8_t)STREAMTCP_DEFAULT_MAX_SYNACK_QUEUED;
    }
    if (!quiet) {
        SCLogConfig("stream \"max-synack-queued\": %"PRIu8, stream_config.max_synack_queued);
    }

    const char *temp_stream_reassembly_memcap_str;
    if (ConfGetValue("stream.reassembly.memcap", &temp_stream_reassembly_memcap_str) == 1) {
        uint64_t stream_reassembly_memcap_copy;
        if (ParseSizeStringU64(temp_stream_reassembly_memcap_str,
                               &stream_reassembly_memcap_copy) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.memcap "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_memcap_str);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(stream_config.reassembly_memcap, stream_reassembly_memcap_copy);
        }
    } else {
        SC_ATOMIC_SET(stream_config.reassembly_memcap , STREAMTCP_DEFAULT_REASSEMBLY_MEMCAP);
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"memcap\": %"PRIu64"",
                    SC_ATOMIC_GET(stream_config.reassembly_memcap));
    }

    const char *temp_stream_reassembly_depth_str;
    if (ConfGetValue("stream.reassembly.depth", &temp_stream_reassembly_depth_str) == 1) {
        if (ParseSizeStringU32(temp_stream_reassembly_depth_str,
                               &stream_config.reassembly_depth) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.depth "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_depth_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_depth = 0;
    }

    if (!quiet) {
        SCLogConfig("stream.reassembly \"depth\": %"PRIu32"", stream_config.reassembly_depth);
    }

    int randomize = 0;
    if ((ConfGetBool("stream.reassembly.randomize-chunk-size", &randomize)) == 0) {
        /* randomize by default if value not set
         * In ut mode we disable, to get predictible test results */
        if (!(RunmodeIsUnittests()))
            randomize = 1;
    }

    if (randomize) {
        const char *temp_rdrange;
        if (ConfGetValue("stream.reassembly.randomize-chunk-range",
                    &temp_rdrange) == 1) {
            if (ParseSizeStringU16(temp_rdrange, &rdrange) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                        "stream.reassembly.randomize-chunk-range "
                        "from conf file - %s.  Killing engine",
                        temp_rdrange);
                exit(EXIT_FAILURE);
            } else if (rdrange >= 100) {
                           FatalError(SC_ERR_FATAL,
                                      "stream.reassembly.randomize-chunk-range "
                                      "must be lower than 100");
            }
        }
    }

    const char *temp_stream_reassembly_toserver_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toserver-chunk-size",
                &temp_stream_reassembly_toserver_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toserver_chunk_size_str,
                               &stream_config.reassembly_toserver_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.toserver-chunk-size "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toserver_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toserver_chunk_size =
            STREAMTCP_DEFAULT_TOSERVER_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toserver_chunk_size +=
            (int) (stream_config.reassembly_toserver_chunk_size *
                   (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }
    const char *temp_stream_reassembly_toclient_chunk_size_str;
    if (ConfGetValue("stream.reassembly.toclient-chunk-size",
                &temp_stream_reassembly_toclient_chunk_size_str) == 1) {
        if (ParseSizeStringU16(temp_stream_reassembly_toclient_chunk_size_str,
                               &stream_config.reassembly_toclient_chunk_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "stream.reassembly.toclient-chunk-size "
                       "from conf file - %s.  Killing engine",
                       temp_stream_reassembly_toclient_chunk_size_str);
            exit(EXIT_FAILURE);
        }
    } else {
        stream_config.reassembly_toclient_chunk_size =
            STREAMTCP_DEFAULT_TOCLIENT_CHUNK_SIZE;
    }

    if (randomize) {
        long int r = RandomGetWrap();
        stream_config.reassembly_toclient_chunk_size +=
            (int) (stream_config.reassembly_toclient_chunk_size *
                   (r * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
    }
    if (!quiet) {
        SCLogConfig("stream.reassembly \"toserver-chunk-size\": %"PRIu16,
            stream_config.reassembly_toserver_chunk_size);
        SCLogConfig("stream.reassembly \"toclient-chunk-size\": %"PRIu16,
            stream_config.reassembly_toclient_chunk_size);
    }

    int enable_raw = 1;
    if (ConfGetBool("stream.reassembly.raw", &enable_raw) == 1) {
        if (!enable_raw) {
            stream_config.stream_init_flags = STREAMTCP_STREAM_FLAG_DISABLE_RAW;
        }
    } else {
        enable_raw = 1;
    }
    if (!quiet)
        SCLogConfig("stream.reassembly.raw: %s", enable_raw ? "enabled" : "disabled");

    /* default to true. Not many ppl (correctly) set up host-os policies, so be permissive. */
    stream_config.liberal_timestamps = true;
    int liberal_timestamps = 0;
    if (ConfGetBool("stream.liberal-timestamps", &liberal_timestamps) == 1) {
        stream_config.liberal_timestamps = liberal_timestamps;
    }
    if (!quiet)
        SCLogConfig("stream.liberal-timestamps: %s", liberal_timestamps ? "enabled" : "disabled");

    /* init the memcap/use tracking */
    StreamTcpInitMemuse();
    StatsRegisterGlobalCounter("tcp.memuse", StreamTcpMemuseCounter);

    StreamTcpReassembleInit(quiet);

    /* set the default free function and flow state function
     * values. */
    FlowSetProtoFreeFunc(IPPROTO_TCP, StreamTcpSessionClear);

#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        SCMutexLock(&ssn_pool_mutex);
        if (ssn_pool == NULL) {
            ssn_pool = PoolThreadInit(1, /* thread */
                    0, /* unlimited */
                    stream_config.prealloc_sessions,
                    sizeof(TcpSession),
                    StreamTcpSessionPoolAlloc,
                    StreamTcpSessionPoolInit, NULL,
                    StreamTcpSessionPoolCleanup, NULL);
        }
        SCMutexUnlock(&ssn_pool_mutex);
    }
#endif
}

void StreamTcpFreeConfig(char quiet)
{
    StreamTcpReassembleFree(quiet);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool != NULL) {
        PoolThreadFree(ssn_pool);
        ssn_pool = NULL;
    }
    SCMutexUnlock(&ssn_pool_mutex);
    SCMutexDestroy(&ssn_pool_mutex);

    SCLogDebug("ssn_pool_cnt %"PRIu64"", ssn_pool_cnt);
}

/** \internal
 *  \brief The function is used to fetch a TCP session from the
 *         ssn_pool, when a TCP SYN is received.
 *
 *  \param p packet starting the new TCP session.
 *  \param id thread pool id
 *
 *  \retval ssn new TCP session.
 */
static TcpSession *StreamTcpNewSession (Packet *p, int id)
{
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        p->flow->protoctx = PoolThreadGetById(ssn_pool, id);
#ifdef DEBUG
        SCMutexLock(&ssn_pool_mutex);
        if (p->flow->protoctx != NULL)
            ssn_pool_cnt++;
        SCMutexUnlock(&ssn_pool_mutex);

        if (unlikely((g_eps_stream_ssn_memcap != UINT64_MAX &&
                      g_eps_stream_ssn_memcap == t_pcapcnt))) {
            SCLogNotice("simulating memcap reached condition for packet %" PRIu64, t_pcapcnt);
            ExceptionPolicyApply(p, stream_config.ssn_memcap_policy, PKT_DROP_REASON_STREAM_MEMCAP);
            return NULL;
        }
#endif
        ssn = (TcpSession *)p->flow->protoctx;
        if (ssn == NULL) {
            SCLogDebug("ssn_pool is empty");
            ExceptionPolicyApply(p, stream_config.ssn_memcap_policy, PKT_DROP_REASON_STREAM_MEMCAP);
            return NULL;
        }

        ssn->state = TCP_NONE;
        ssn->reassembly_depth = stream_config.reassembly_depth;
        ssn->tcp_packet_flags = p->tcph ? p->tcph->th_flags : 0;
        ssn->server.flags = stream_config.stream_init_flags;
        ssn->client.flags = stream_config.stream_init_flags;

        StreamingBuffer x = STREAMING_BUFFER_INITIALIZER(&stream_config.sbcnf);
        ssn->client.sb = x;
        ssn->server.sb = x;

        if (PKT_IS_TOSERVER(p)) {
            ssn->client.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->client.tcp_init_flags = p->tcph->th_flags;
            ssn->server.tcp_flags = 0;
            ssn->server.tcp_init_flags = 0;
        } else if (PKT_IS_TOCLIENT(p)) {
            ssn->server.tcp_flags = p->tcph ? p->tcph->th_flags : 0;
            ssn->server.tcp_init_flags = p->tcph->th_flags;
            ssn->client.tcp_flags = 0;
            ssn->client.tcp_init_flags = 0;
        }
    }

    return ssn;
}

static void StreamTcpPacketSetState(Packet *p, TcpSession *ssn,
                                           uint8_t state)
{
    if (state == ssn->state || PKT_IS_PSEUDOPKT(p))
        return;

    ssn->pstate = ssn->state;
    ssn->state = state;

    /* update the flow state */
    switch(ssn->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            FlowUpdateState(p->flow, FLOW_STATE_ESTABLISHED);
            break;
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
        case TCP_CLOSED:
            FlowUpdateState(p->flow, FLOW_STATE_CLOSED);
            break;
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
 *  \brief macro to update last_ack only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param ack ACK value to test and set
 */
#define StreamTcpUpdateLastAck(ssn, stream, ack) { \
    if (SEQ_GT((ack), (stream)->last_ack)) \
    { \
        SCLogDebug("ssn %p: last_ack set to %"PRIu32", moved %u forward", (ssn), (ack), (ack) - (stream)->last_ack); \
        if ((SEQ_LEQ((stream)->last_ack, (stream)->next_seq) && SEQ_GT((ack),(stream)->next_seq))) { \
            SCLogDebug("last_ack just passed next_seq: %u (was %u) > %u", (ack), (stream)->last_ack, (stream)->next_seq); \
        } else { \
            SCLogDebug("next_seq (%u) <> last_ack now %d", (stream)->next_seq, (int)(stream)->next_seq - (ack)); \
        }\
        (stream)->last_ack = (ack); \
        StreamTcpSackPruneList((stream)); \
    } else { \
        SCLogDebug("ssn %p: no update: ack %u, last_ack %"PRIu32", next_seq %u (state %u)", \
                    (ssn), (ack), (stream)->last_ack, (stream)->next_seq, (ssn)->state); \
    }\
}

#define StreamTcpAsyncLastAckUpdate(ssn, stream) {                              \
    if ((ssn)->flags & STREAMTCP_FLAG_ASYNC) {                                  \
        if (SEQ_GT((stream)->next_seq, (stream)->last_ack)) {                   \
            uint32_t ack_diff = (stream)->next_seq - (stream)->last_ack;        \
            (stream)->last_ack += ack_diff;                                     \
            SCLogDebug("ssn %p: ASYNC last_ack set to %"PRIu32", moved %u forward",     \
                    (ssn), (stream)->next_seq, ack_diff);                               \
        }                                                                       \
    }                                                                           \
}

#define StreamTcpUpdateNextSeq(ssn, stream, seq) {                      \
    (stream)->next_seq = seq;                                           \
    SCLogDebug("ssn %p: next_seq %" PRIu32, (ssn), (stream)->next_seq); \
    StreamTcpAsyncLastAckUpdate((ssn), (stream));                       \
}

/**
 *  \brief macro to update next_win only if the new value is higher
 *
 *  \param ssn session
 *  \param stream stream to update
 *  \param win window value to test and set
 */
#define StreamTcpUpdateNextWin(ssn, stream, win) { \
    uint32_t sacked_size__ = StreamTcpSackedSize((stream)); \
    if (SEQ_GT(((win) + sacked_size__), (stream)->next_win)) { \
        (stream)->next_win = ((win) + sacked_size__); \
        SCLogDebug("ssn %p: next_win set to %"PRIu32, (ssn), (stream)->next_win); \
    } \
}

static inline void StreamTcpCloseSsnWithReset(Packet *p, TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_CLOSED_BY_RST;
    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
    SCLogDebug("ssn %p: (state: %s) Reset received and state changed to "
            "TCP_CLOSED", ssn, StreamTcpStateAsString(ssn->state));
}

static int StreamTcpPacketIsRetransmission(TcpStream *stream, Packet *p)
{
    if (p->payload_len == 0)
        SCReturnInt(0);

    /* retransmission of already partially ack'd data */
    if (SEQ_LT(TCP_GET_SEQ(p), stream->last_ack) && SEQ_GT((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack))
    {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    /* retransmission of already ack'd data */
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->last_ack)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(1);
    }

    /* retransmission of in flight data */
    if (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), stream->next_seq)) {
        StreamTcpSetEvent(p, STREAM_PKT_RETRANSMISSION);
        SCReturnInt(2);
    }

    SCLogDebug("seq %u payload_len %u => %u, last_ack %u, next_seq %u", TCP_GET_SEQ(p),
            p->payload_len, (TCP_GET_SEQ(p) + p->payload_len), stream->last_ack, stream->next_seq);
    SCReturnInt(0);
}

/**
 *  \internal
 *  \brief  Function to handle the TCP_CLOSED or NONE state. The function handles
 *          packets while the session state is None which means a newly
 *          initialized structure, or a fully closed session.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Stream Thread module registered to handle the stream handling
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn,
        PacketQueueNoLock *pq)
{
    if (p->tcph->th_flags & TH_RST) {
        if (stream_config.midstream == FALSE) {
            StreamTcpSetEvent(p, STREAM_RST_BUT_NO_SESSION);
            SCLogDebug("RST packet received, no session setup");
            return -1;
        }
        ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
        if (ssn == NULL) {
            StatsIncr(tv, stt->counter_tcp_ssn_memcap);
            return -1;
        }
        StatsIncr(tv, stt->counter_tcp_sessions);
        StatsIncr(tv, stt->counter_tcp_midstream_pickups);

        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;

        if (PKT_IS_TOSERVER(p)) {
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
            SCLogDebug("ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
        } else {
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
            SCLogDebug("ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
        }
        StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now TCP_CLOSED", ssn);

    } else if (p->tcph->th_flags & TH_FIN) {
        if (stream_config.midstream == FALSE) {
            StreamTcpSetEvent(p, STREAM_FIN_BUT_NO_SESSION);
            SCLogDebug("FIN packet received, no session setup");
            return -1;
        }
        ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
        if (ssn == NULL) {
            StatsIncr(tv, stt->counter_tcp_ssn_memcap);
            return -1;
        }
        StatsIncr(tv, stt->counter_tcp_sessions);
        StatsIncr(tv, stt->counter_tcp_midstream_pickups);

        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now TCP_CLOSE_WAIT", ssn);
        } else {
            StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
            SCLogDebug("ssn %p: =~ midstream picked ssn state is now TCP_FIN_WAIT1", ssn);
        }

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        /* Drop reason will only be used if midstream policy is set to fail closed */
        ExceptionPolicyApply(p, stream_config.midstream_policy, PKT_DROP_REASON_STREAM_MIDSTREAM);

        if (stream_config.midstream == FALSE && stream_config.async_oneside == FALSE) {
            SCLogDebug("Midstream not enabled, so won't pick up a session");
            return 0;
        }
        if (!(stream_config.midstream_policy == EXCEPTION_POLICY_NOT_SET ||
                    stream_config.midstream_policy == EXCEPTION_POLICY_PASS_FLOW)) {
            SCLogDebug("Midstream policy not permissive, so won't pick up a session");
            return 0;
        }
        SCLogDebug("midstream picked up");

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
            StatsIncr(tv, stt->counter_tcp_midstream_pickups);
        }

        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                "TCP_SYN_RECV", ssn);
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM;
        /* Flag used to change the direct in the later stage in the session */
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_SYNACK;
        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        /* sequence number & window */
        ssn->server.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.window = TCP_GET_WINDOW(p);
        SCLogDebug("ssn %p: server window %u", ssn, ssn->server.window);

        ssn->client.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        ssn->client.last_ack = TCP_GET_ACK(p);
        ssn->server.last_ack = TCP_GET_SEQ(p);

        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

        /** If the client has a wscale option the server had it too,
         *  so set the wscale for the server to max. Otherwise none
         *  will have the wscale opt just like it should. */
        if (TCP_HAS_WSCALE(p)) {
            ssn->client.wscale = TCP_GET_WSCALE(p);
            ssn->server.wscale = TCP_WSCALE_MAX;
            SCLogDebug("ssn %p: wscale enabled. client %u server %u",
                    ssn, ssn->client.wscale, ssn->server.wscale);
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
        if (TCP_HAS_TS(p)) {
            ssn->server.last_ts = TCP_GET_TSVAL(p);
            ssn->client.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                    "ssn->client.last_ts %" PRIu32"", ssn,
                    ssn->server.last_ts, ssn->client.last_ts);

            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->server.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
            SCLogDebug("ssn %p: SYN/ACK with SACK permitted, assuming "
                    "SACK permitted for both sides", ssn);
        }
        return 0;

    } else if (p->tcph->th_flags & TH_SYN) {
        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }

            StatsIncr(tv, stt->counter_tcp_sessions);
        }

        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_SENT);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_SENT", ssn);

        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p);
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = ssn->client.isn + 1;

        /* Set the stream timestamp value, if packet has timestamp option
         * enabled. */
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            SCLogDebug("ssn %p: %02x", ssn, ssn->client.last_ts);

            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
        }

        ssn->server.window = TCP_GET_WINDOW(p);
        if (TCP_HAS_WSCALE(p)) {
            ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
            ssn->server.wscale = TCP_GET_WSCALE(p);
        }

        if (TCP_GET_SACKOK(p) == 1) {
            ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            SCLogDebug("ssn %p: SACK permitted on SYN packet", ssn);
        }

        if (TCP_HAS_TFO(p)) {
            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            if (p->payload_len) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
                SCLogDebug("ssn: %p (TFO) [len: %d] isn %u base_seq %u next_seq %u payload len %u",
                        ssn, p->tcpvars.tfo.len, ssn->client.isn, ssn->client.base_seq, ssn->client.next_seq, p->payload_len);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);
            }
        }

        SCLogDebug("ssn %p: ssn->client.isn %" PRIu32 ", "
                "ssn->client.next_seq %" PRIu32 ", ssn->client.last_ack "
                "%"PRIu32"", ssn, ssn->client.isn, ssn->client.next_seq,
                ssn->client.last_ack);

    } else if (p->tcph->th_flags & TH_ACK) {
        /* Drop reason will only be used if midstream policy is set to fail closed */
        ExceptionPolicyApply(p, stream_config.midstream_policy, PKT_DROP_REASON_STREAM_MIDSTREAM);

        if (stream_config.midstream == FALSE) {
            SCLogDebug("Midstream not enabled, so won't pick up a session");
            return 0;
        }
        if (!(stream_config.midstream_policy == EXCEPTION_POLICY_NOT_SET ||
                    stream_config.midstream_policy == EXCEPTION_POLICY_PASS_FLOW)) {
            SCLogDebug("Midstream policy not permissive, so won't pick up a session");
            return 0;
        }
        SCLogDebug("midstream picked up");

        if (ssn == NULL) {
            ssn = StreamTcpNewSession(p, stt->ssn_pool_id);
            if (ssn == NULL) {
                StatsIncr(tv, stt->counter_tcp_ssn_memcap);
                return -1;
            }
            StatsIncr(tv, stt->counter_tcp_sessions);
            StatsIncr(tv, stt->counter_tcp_midstream_pickups);
        }
        /* set the state */
        StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        SCLogDebug("ssn %p: =~ midstream picked ssn state is now "
                "TCP_ESTABLISHED", ssn);

        ssn->flags = STREAMTCP_FLAG_MIDSTREAM;
        ssn->flags |= STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        if (stream_config.async_oneside) {
            SCLogDebug("ssn %p: =~ ASYNC", ssn);
            ssn->flags |= STREAMTCP_FLAG_ASYNC;
        }

        /** window scaling for midstream pickups, we can't do much other
         *  than assume that it's set to the max value: 14 */
        ssn->client.wscale = TCP_WSCALE_MAX;
        ssn->server.wscale = TCP_WSCALE_MAX;

        /* set the sequence numbers and window */
        ssn->client.isn = TCP_GET_SEQ(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        ssn->client.last_ack = TCP_GET_SEQ(p);
        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
        SCLogDebug("ssn %p: ssn->client.isn %u, ssn->client.next_seq %u",
                ssn, ssn->client.isn, ssn->client.next_seq);

        ssn->server.isn = TCP_GET_ACK(p) - 1;
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = TCP_GET_ACK(p);
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: ssn->client.next_win %"PRIu32", "
                "ssn->server.next_win %"PRIu32"", ssn,
                ssn->client.next_win, ssn->server.next_win);
        SCLogDebug("ssn %p: ssn->client.last_ack %"PRIu32", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->client.last_ack, ssn->server.last_ack);

        /* Set the timestamp value for both streams, if packet has timestamp
         * option enabled.*/
        if (TCP_HAS_TS(p)) {
            ssn->client.last_ts = TCP_GET_TSVAL(p);
            ssn->server.last_ts = TCP_GET_TSECR(p);
            SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                    "ssn->client.last_ts %" PRIu32"", ssn,
                    ssn->server.last_ts, ssn->client.last_ts);

            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;

            ssn->client.last_pkt_ts = p->ts.tv_sec;
            if (ssn->server.last_ts == 0)
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            if (ssn->client.last_ts == 0)
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;

        } else {
            ssn->server.last_ts = 0;
            ssn->client.last_ts = 0;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: assuming SACK permitted for both sides", ssn);

    } else {
        SCLogDebug("default case");
    }

    return 0;
}

/** \internal
 *  \brief Setup TcpStateQueue based on SYN/ACK packet
 */
static inline void StreamTcp3whsSynAckToStateQueue(Packet *p, TcpStateQueue *q)
{
    q->flags = 0;
    q->wscale = 0;
    q->ts = 0;
    q->win = TCP_GET_WINDOW(p);
    q->seq = TCP_GET_SEQ(p);
    q->ack = TCP_GET_ACK(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1)
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;

    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSVAL(p);
    }
}

/** \internal
 *  \brief Find the Queued SYN/ACK that is the same as this SYN/ACK
 *  \retval q or NULL */
static TcpStateQueue *StreamTcp3whsFindSynAckBySynAck(TcpSession *ssn, Packet *p)
{
    TcpStateQueue *q = ssn->queue;
    TcpStateQueue search;

    StreamTcp3whsSynAckToStateQueue(p, &search);

    while (q != NULL) {
        if (search.flags == q->flags &&
            search.wscale == q->wscale &&
            search.win == q->win &&
            search.seq == q->seq &&
            search.ack == q->ack &&
            search.ts == q->ts) {
            return q;
        }

        q = q->next;
    }

    return q;
}

static int StreamTcp3whsQueueSynAck(TcpSession *ssn, Packet *p)
{
    /* first see if this is already in our list */
    if (StreamTcp3whsFindSynAckBySynAck(ssn, p) != NULL)
        return 0;

    if (ssn->queue_len == stream_config.max_synack_queued) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue limit reached", ssn);
        StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_FLOOD);
        return -1;
    }

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpStateQueue)) == 0) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: stream memcap reached", ssn);
        return -1;
    }

    TcpStateQueue *q = SCMalloc(sizeof(*q));
    if (unlikely(q == NULL)) {
        SCLogDebug("ssn %p: =~ SYN/ACK queue failed: alloc failed", ssn);
        return -1;
    }
    memset(q, 0x00, sizeof(*q));
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpStateQueue));

    StreamTcp3whsSynAckToStateQueue(p, q);

    /* put in list */
    q->next = ssn->queue;
    ssn->queue = q;
    ssn->queue_len++;
    return 0;
}

/** \internal
 *  \brief Find the Queued SYN/ACK that goes with this ACK
 *  \retval q or NULL */
static TcpStateQueue *StreamTcp3whsFindSynAckByAck(TcpSession *ssn, Packet *p)
{
    uint32_t ack = TCP_GET_SEQ(p);
    uint32_t seq = TCP_GET_ACK(p) - 1;
    TcpStateQueue *q = ssn->queue;

    while (q != NULL) {
        if (seq == q->seq &&
            ack == q->ack) {
            return q;
        }

        q = q->next;
    }

    return NULL;
}

/** \internal
 *  \brief Update SSN after receiving a valid SYN/ACK
 *
 *  Normally we update the SSN from the SYN/ACK packet. But in case
 *  of queued SYN/ACKs, we can use one of those.
 *
 *  \param ssn TCP session
 *  \param p Packet
 *  \param q queued state if used, NULL otherwise
 *
 *  To make sure all SYN/ACK based state updates are in one place,
 *  this function can updated based on Packet or TcpStateQueue, where
 *  the latter takes precedence.
 */
static void StreamTcp3whsSynAckUpdate(TcpSession *ssn, Packet *p, TcpStateQueue *q)
{
    TcpStateQueue update;
    if (likely(q == NULL)) {
        StreamTcp3whsSynAckToStateQueue(p, &update);
        q = &update;
    }

    if (ssn->state != TCP_SYN_RECV) {
        /* update state */
        StreamTcpPacketSetState(p, ssn, TCP_SYN_RECV);
        SCLogDebug("ssn %p: =~ ssn state is now TCP_SYN_RECV", ssn);
    }
    /* sequence number & window */
    ssn->server.isn = q->seq;
    STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
    ssn->server.next_seq = ssn->server.isn + 1;

    ssn->client.window = q->win;
    SCLogDebug("ssn %p: window %" PRIu32 "", ssn, ssn->server.window);

    /* Set the timestamp values used to validate the timestamp of
     * received packets.*/
    if ((q->flags & STREAMTCP_QUEUE_FLAG_TS) &&
            (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
    {
        ssn->server.last_ts = q->ts;
        SCLogDebug("ssn %p: ssn->server.last_ts %" PRIu32" "
                "ssn->client.last_ts %" PRIu32"", ssn,
                ssn->server.last_ts, ssn->client.last_ts);
        ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
        ssn->server.last_pkt_ts = q->pkt_ts;
        if (ssn->server.last_ts == 0)
            ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    } else {
        ssn->client.last_ts = 0;
        ssn->server.last_ts = 0;
        ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
    }

    ssn->client.last_ack = q->ack;
    ssn->server.last_ack = ssn->server.isn + 1;

    /** check for the presense of the ws ptr to determine if we
     *  support wscale at all */
    if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
            (q->flags & STREAMTCP_QUEUE_FLAG_WS))
    {
        ssn->client.wscale = q->wscale;
    } else {
        ssn->client.wscale = 0;
    }

    if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
            (q->flags & STREAMTCP_QUEUE_FLAG_SACK)) {
        ssn->flags |= STREAMTCP_FLAG_SACKOK;
        SCLogDebug("ssn %p: SACK permitted for session", ssn);
    } else {
        ssn->flags &= ~STREAMTCP_FLAG_SACKOK;
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
}

/** \internal
 *  \brief detect timestamp anomalies when processing responses to the
 *         SYN packet.
 *  \retval true packet is ok
 *  \retval false packet is bad
 */
static inline bool StateSynSentValidateTimestamp(TcpSession *ssn, Packet *p)
{
    /* we only care about evil server here, so skip TS packets */
    if (PKT_IS_TOSERVER(p) || !(TCP_HAS_TS(p))) {
        return true;
    }

    TcpStream *receiver_stream = &ssn->client;
    uint32_t ts_echo = TCP_GET_TSECR(p);
    if ((receiver_stream->flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) != 0) {
        if (receiver_stream->last_ts != 0 && ts_echo != 0 &&
            ts_echo != receiver_stream->last_ts)
        {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,
                    ts_echo, receiver_stream->last_ts);
            return false;
        }
    } else {
        if (receiver_stream->last_ts == 0 && ts_echo != 0) {
            SCLogDebug("ssn %p: BAD TSECR echo %u recv %u", ssn,
                    ts_echo, receiver_stream->last_ts);
            return false;
        }
    }
    return true;
}

static void TcpStateQueueInitFromSsnSyn(const TcpSession *ssn, TcpStateQueue *q)
{
    BUG_ON(ssn->state != TCP_SYN_SENT); // TODO
    memset(q, 0, sizeof(*q));

    /* SYN won't use wscale yet. So window should be limited to 16 bits. */
    DEBUG_VALIDATE_BUG_ON(ssn->server.window > UINT16_MAX);
    q->win = (uint16_t)ssn->server.window;

    q->pkt_ts = ssn->client.last_pkt_ts;

    if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;
    }
    if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = ssn->server.wscale;
    }
    if (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = ssn->client.last_ts;
    }

    SCLogDebug("ssn %p: state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u", ssn, q, q->seq, q->win,
            BOOL2STR(q->flags & STREAMTCP_QUEUE_FLAG_TS), q->ts);
}

static void TcpStateQueueInitFromPktSyn(const Packet *p, TcpStateQueue *q)
{
#if defined(DEBUG_VALIDATION) || defined(DEBUG)
    const TcpSession *ssn = p->flow->protoctx;
    BUG_ON(ssn->state != TCP_SYN_SENT);
#endif
    memset(q, 0, sizeof(*q));

    q->win = TCP_GET_WINDOW(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1) {
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;
    }
    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSVAL(p);
    }

#if defined(DEBUG)
    SCLogDebug("ssn %p: state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u", ssn, q, q->seq, q->win,
            BOOL2STR(q->flags & STREAMTCP_QUEUE_FLAG_TS), q->ts);
#endif
}

static void TcpStateQueueInitFromPktSynAck(const Packet *p, TcpStateQueue *q)
{
#if defined(DEBUG_VALIDATION) || defined(DEBUG)
    const TcpSession *ssn = p->flow->protoctx;
    if ((ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) == 0)
        BUG_ON(ssn->state != TCP_SYN_SENT);
    else
        BUG_ON(ssn->state != TCP_ESTABLISHED);
#endif
    memset(q, 0, sizeof(*q));

    q->win = TCP_GET_WINDOW(p);
    q->pkt_ts = p->ts.tv_sec;

    if (TCP_GET_SACKOK(p) == 1) {
        q->flags |= STREAMTCP_QUEUE_FLAG_SACK;
    }
    if (TCP_HAS_WSCALE(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_WS;
        q->wscale = TCP_GET_WSCALE(p);
    }
    if (TCP_HAS_TS(p)) {
        q->flags |= STREAMTCP_QUEUE_FLAG_TS;
        q->ts = TCP_GET_TSECR(p);
    }

#if defined(DEBUG)
    SCLogDebug("ssn %p: state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u", ssn, q, q->seq, q->win,
            BOOL2STR(q->flags & STREAMTCP_QUEUE_FLAG_TS), q->ts);
#endif
}

/** \internal
 *  \brief Find the Queued SYN that is the same as this SYN/ACK
 *  \retval q or NULL */
static const TcpStateQueue *StreamTcp3whsFindSyn(const TcpSession *ssn, TcpStateQueue *s)
{
    SCLogDebug("ssn %p: search state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u", ssn, s, s->seq, s->win,
            BOOL2STR(s->flags & STREAMTCP_QUEUE_FLAG_TS), s->ts);

    for (const TcpStateQueue *q = ssn->queue; q != NULL; q = q->next) {
        SCLogDebug("ssn %p: queue state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u", ssn, q, q->seq,
                q->win, BOOL2STR(q->flags & STREAMTCP_QUEUE_FLAG_TS), q->ts);
        if ((s->flags & STREAMTCP_QUEUE_FLAG_TS) == (q->flags & STREAMTCP_QUEUE_FLAG_TS) &&
                s->ts == q->ts) {
            return q;
        }
    }
    return NULL;
}

/** \note the SEQ values *must* be the same */
static int StreamTcp3whsStoreSyn(TcpSession *ssn, Packet *p)
{
    TcpStateQueue search;
    TcpStateQueueInitFromSsnSyn(ssn, &search);

    /* first see if this is already in our list */
    if (ssn->queue != NULL && StreamTcp3whsFindSyn(ssn, &search) != NULL)
        return 0;

    if (ssn->queue_len == stream_config.max_synack_queued) { // TODO
        SCLogDebug("ssn %p: =~ SYN queue limit reached", ssn);
        StreamTcpSetEvent(p, STREAM_3WHS_SYN_FLOOD);
        return -1;
    }

    if (StreamTcpCheckMemcap((uint32_t)sizeof(TcpStateQueue)) == 0) {
        SCLogDebug("ssn %p: =~ SYN queue failed: stream memcap reached", ssn);
        return -1;
    }

    TcpStateQueue *q = SCCalloc(1, sizeof(*q));
    if (unlikely(q == NULL)) {
        SCLogDebug("ssn %p: =~ SYN queue failed: alloc failed", ssn);
        return -1;
    }
    StreamTcpIncrMemuse((uint64_t)sizeof(TcpStateQueue));

    *q = search;
    /* put in list */
    q->next = ssn->queue;
    ssn->queue = q;
    ssn->queue_len++;
    return 0;
}

static inline void StreamTcp3whsStoreSynApplyToSsn(TcpSession *ssn, const TcpStateQueue *q)
{
    if (q->flags & STREAMTCP_QUEUE_FLAG_TS) {
        ssn->client.last_pkt_ts = q->pkt_ts;
        ssn->client.last_ts = q->ts;
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
        SCLogDebug("ssn: %p client.last_ts updated to %u", ssn, ssn->client.last_ts);
    }
    if (q->flags & STREAMTCP_QUEUE_FLAG_WS) {
        ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
        ssn->server.wscale = q->wscale;
    } else {
        ssn->flags &= STREAMTCP_FLAG_SERVER_WSCALE;
        ssn->server.wscale = 0;
    }
    ssn->server.window = q->win;

    if (q->flags & STREAMTCP_QUEUE_FLAG_SACK) {
        ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
    } else {
        ssn->flags &= ~STREAMTCP_FLAG_CLIENT_SACKOK;
    }
}

/**
 *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
 *          SYN, SYN/ACK, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn,
        PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    SCLogDebug("ssn %p: pkt received: %s", ssn, PKT_IS_TOCLIENT(p) ? "toclient" : "toserver");

    /* SYN/ACK */
    if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK received on 4WHS session", ssn);

            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->server.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_ACK);

                SCLogDebug("ssn %p: 4WHS ACK mismatch, packet ACK %"PRIu32""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_ACK(p), ssn->server.isn + 1);
                return -1;
            }

            /* Check if the SYN/ACK packet SEQ's the *FIRST* received SYN
             * packet. */
            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
                StreamTcpSetEvent(p, STREAM_4WHS_SYNACK_WITH_WRONG_SYN);

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
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->client, ssn->client.isn);
            ssn->client.next_seq = ssn->client.isn + 1;

            ssn->server.window = TCP_GET_WINDOW(p);
            SCLogDebug("ssn %p: 4WHS window %" PRIu32 "", ssn,
                    ssn->client.window);

            /* Set the timestamp values used to validate the timestamp of
             * received packets. */
            if ((TCP_HAS_TS(p)) &&
                    (ssn->server.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
            {
                ssn->client.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: 4WHS ssn->client.last_ts %" PRIu32" "
                        "ssn->server.last_ts %" PRIu32"", ssn,
                        ssn->client.last_ts, ssn->server.last_ts);
                ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
                ssn->client.last_pkt_ts = p->ts.tv_sec;
                if (ssn->client.last_ts == 0)
                    ssn->client.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            } else {
                ssn->server.last_ts = 0;
                ssn->client.last_ts = 0;
                ssn->server.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
            }

            ssn->server.last_ack = TCP_GET_ACK(p);
            ssn->client.last_ack = ssn->client.isn + 1;

            /** check for the presense of the ws ptr to determine if we
             *  support wscale at all */
            if ((ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) &&
                    (TCP_HAS_WSCALE(p)))
            {
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->server.wscale = 0;
            }

            if ((ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) &&
                    TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
                SCLogDebug("ssn %p: SACK permitted for 4WHS session", ssn);
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
            return 0;
        }

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_IN_WRONG_DIRECTION);
            SCLogDebug("ssn %p: SYN/ACK received in the wrong direction", ssn);
            return -1;
        }

        if (!(TCP_HAS_TFO(p) || (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN))) {
            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                        "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                        ssn->client.isn + 1);
                return -1;
            }
        } else {
            if (SEQ_EQ(TCP_GET_ACK(p), ssn->client.next_seq)) {
                SCLogDebug("ssn %p: (TFO) ACK matches next_seq, packet ACK %" PRIu32 " == "
                           "%" PRIu32 " from stream",
                        ssn, TCP_GET_ACK(p), ssn->client.next_seq);
            } else if (SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1)) {
                SCLogDebug("ssn %p: (TFO) ACK matches ISN+1, packet ACK %" PRIu32 " == "
                           "%" PRIu32 " from stream",
                        ssn, TCP_GET_ACK(p), ssn->client.isn + 1);
                ssn->client.next_seq = ssn->client.isn;
                SCLogDebug("ssn %p: (TFO) next_seq reset to isn (%u)", ssn, ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_TFO_DATA_IGNORED);
            } else {
                StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_WITH_WRONG_ACK);
                SCLogDebug("ssn %p: (TFO) ACK mismatch, packet ACK %" PRIu32 " != "
                        "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                        ssn->client.next_seq);
                return -1;
            }
            ssn->flags |= STREAMTCP_FLAG_TCP_FAST_OPEN;
            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
        }

        const bool ts_mismatch = !StateSynSentValidateTimestamp(ssn, p);
        if (ts_mismatch) {
            SCLogDebug("ssn %p: ts_mismatch:%s", ssn, BOOL2STR(ts_mismatch));
            if (ssn->queue) {
                TcpStateQueue search;
                TcpStateQueueInitFromPktSynAck(p, &search);

                const TcpStateQueue *q = StreamTcp3whsFindSyn(ssn, &search);
                if (q == NULL) {
                    SCLogDebug("not found: mismatch");
                    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
                    return -1;
                }
                SCLogDebug("ssn %p: found queued SYN state:%p, isn:%u/win:%u/has_ts:%s/tsval:%u",
                        ssn, q, q->seq, q->win, BOOL2STR(q->flags & STREAMTCP_QUEUE_FLAG_TS),
                        q->ts);

                StreamTcp3whsStoreSynApplyToSsn(ssn, q);

            } else {
                SCLogDebug("not found: no queue");
                StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
                return -1;
            }
        }

        /* clear ssn->queue on state change: TcpSession can be reused by SYN/ACK */
        StreamTcp3wsFreeQueue(ssn);

        StreamTcp3whsSynAckUpdate(ssn, p, /* no queue override */NULL);
        return 0;
    }

    /* check for bad responses */
    if (StateSynSentValidateTimestamp(ssn, p) == false) {
        StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
        return -1;
    }

    /* RST */
    if (p->tcph->th_flags & TH_RST) {

        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) && SEQ_EQ(TCP_GET_WINDOW(p), 0) &&
                    SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1))) {
                SCLogDebug("ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
                StreamTcpCloseSsnWithReset(p, ssn);
            }
        } else {
            ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
            SCLogDebug("ssn->client.flags |= STREAMTCP_STREAM_FLAG_RST_RECV");
            StreamTcpCloseSsnWithReset(p, ssn);
        }

        /* FIN */
    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent", ssn);
        if (ssn->flags & STREAMTCP_FLAG_4WHS) {
            SCLogDebug("ssn %p: SYN packet on state SYN_SENT... resent of "
                    "4WHS SYN", ssn);
        }

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
            STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
            ssn->server.next_seq = ssn->server.isn + 1;

            /* Set the stream timestamp value, if packet has timestamp
             * option enabled. */
            if (TCP_HAS_TS(p)) {
                ssn->server.last_ts = TCP_GET_TSVAL(p);
                SCLogDebug("ssn %p: %02x", ssn, ssn->server.last_ts);

                if (ssn->server.last_ts == 0)
                    ssn->server.flags |= STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
                ssn->server.last_pkt_ts = p->ts.tv_sec;
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_TIMESTAMP;
            }

            ssn->server.window = TCP_GET_WINDOW(p);
            if (TCP_HAS_WSCALE(p)) {
                ssn->flags |= STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = TCP_GET_WSCALE(p);
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_SERVER_WSCALE;
                ssn->server.wscale = 0;
            }

            if (TCP_GET_SACKOK(p) == 1) {
                ssn->flags |= STREAMTCP_FLAG_CLIENT_SACKOK;
            } else {
                ssn->flags &= ~STREAMTCP_FLAG_CLIENT_SACKOK;
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
        } else if (PKT_IS_TOSERVER(p)) {
            /* on a SYN resend we queue up the SYN's until a SYN/ACK moves the state
             * to SYN_RECV. We update the ssn to the most recent, as it is most likely
             * to be correct. */

            TcpStateQueue syn_pkt, syn_ssn;
            TcpStateQueueInitFromPktSyn(p, &syn_pkt);
            TcpStateQueueInitFromSsnSyn(ssn, &syn_ssn);

            if (memcmp(&syn_pkt, &syn_ssn, sizeof(TcpStateQueue)) != 0) {
                /* store the old session settings */
                StreamTcp3whsStoreSyn(ssn, p);
                SCLogDebug("ssn %p: Retransmitted SYN. Updating ssn from packet %" PRIu64
                           ". Stored previous state",
                        ssn, p->pcap_cnt);
            }
            StreamTcp3whsStoreSynApplyToSsn(ssn, &syn_pkt);
        }
    } else if (p->tcph->th_flags & TH_ACK) {
        /* Handle the asynchronous stream, when we receive a  SYN packet
           and now istead of receving a SYN/ACK we receive a ACK from the
           same host, which sent the SYN, this suggests the ASNYC streams.*/
        if (stream_config.async_oneside == FALSE)
            return 0;

        /* we are in AYNC (one side) mode now. */

        /* one side async means we won't see a SYN/ACK, so we can
         * only check the SYN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
            StreamTcpSetEvent(p, STREAM_3WHS_ASYNC_WRONG_SEQ);

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
        STREAMTCP_SET_RA_BASE_SEQ(&ssn->server, ssn->server.isn);
        ssn->server.next_seq = ssn->server.isn + 1;
        ssn->server.last_ack = ssn->server.next_seq;
        ssn->server.next_win = ssn->server.last_ack;

        SCLogDebug("ssn %p: synsent => Asynchronous stream, packet SEQ"
                " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                "ssn->client.next_seq %" PRIu32 ""
                ,ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                + p->payload_len, ssn->client.next_seq);

        /* if SYN had wscale, assume it to be supported. Otherwise
         * we know it not to be supported. */
        if (ssn->flags & STREAMTCP_FLAG_SERVER_WSCALE) {
            ssn->client.wscale = TCP_WSCALE_MAX;
        }

        /* Set the timestamp values used to validate the timestamp of
         * received packets.*/
        if (TCP_HAS_TS(p) &&
                (ssn->client.flags & STREAMTCP_STREAM_FLAG_TIMESTAMP))
        {
            ssn->flags |= STREAMTCP_FLAG_TIMESTAMP;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_TIMESTAMP;
            ssn->client.last_pkt_ts = p->ts.tv_sec;
        } else {
            ssn->client.last_ts = 0;
            ssn->client.flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
        }

        if (ssn->flags & STREAMTCP_FLAG_CLIENT_SACKOK) {
            ssn->flags |= STREAMTCP_FLAG_SACKOK;
        }

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: default case", ssn);
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
 *
 *  \retval  0 ok
 *  \retval -1 error
 */

static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn,
        PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        uint8_t reset = TRUE;
        /* After receiveing the RST in SYN_RECV state and if detection
           evasion flags has been set, then the following operating
           systems will not closed the connection. As they consider the
           packet as stray packet and not belonging to the current
           session, for more information check
           http://www.packetstan.com/2010/06/recently-ive-been-on-campaign-to-make.html */
        if (ssn->flags & STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT) {
            if (PKT_IS_TOSERVER(p)) {
                if ((ssn->server.os_policy == OS_POLICY_LINUX) ||
                        (ssn->server.os_policy == OS_POLICY_OLD_LINUX) ||
                        (ssn->server.os_policy == OS_POLICY_SOLARIS))
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                            " not resetting the connection !!");
                }
            } else {
                if ((ssn->client.os_policy == OS_POLICY_LINUX) ||
                        (ssn->client.os_policy == OS_POLICY_OLD_LINUX) ||
                        (ssn->client.os_policy == OS_POLICY_SOLARIS))
                {
                    reset = FALSE;
                    SCLogDebug("Detection evasion has been attempted, so"
                            " not resetting the connection !!");
                }
            }
        }

        if (reset == TRUE) {
            StreamTcpCloseSsnWithReset(p, ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /* FIN is handled in the same way as in TCP_ESTABLISHED case */;
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state SYN_RECV. resent", ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_TOSERVER_ON_SYN_RECV);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_3WHS_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN/ACK packet, server resend with different ISN. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                    ssn->client.isn);

            if (StreamTcp3whsQueueSynAck(ssn, p) == -1)
                return -1;
            SCLogDebug("ssn %p: queued different SYN/ACK", ssn);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state SYN_RECV... resent", ssn);

        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_TOCLIENT_ON_SYN_RECV);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_SYN_RESEND_DIFF_SEQ_ON_SYN_RECV);
            return -1;
        }

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->queue_len) {
            SCLogDebug("ssn %p: checking ACK against queued SYN/ACKs", ssn);
            TcpStateQueue *q = StreamTcp3whsFindSynAckByAck(ssn, p);
            if (q != NULL) {
                SCLogDebug("ssn %p: here we update state against queued SYN/ACK", ssn);
                StreamTcp3whsSynAckUpdate(ssn, p, /* using queue to update state */q);
            } else {
                SCLogDebug("ssn %p: none found, now checking ACK against original SYN/ACK (state)", ssn);
            }
        }


        /* If the timestamp option is enabled for both the streams, then
         * validate the received packet timestamp value against the
         * stream->last_ts. If the timestamp is valid then process the
         * packet normally otherwise the drop the packet (RFC 1323)*/
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!(StreamTcpValidateTimestamp(ssn, p))) {
                return -1;
            }
        }

        if ((ssn->flags & STREAMTCP_FLAG_4WHS) && PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: ACK received on 4WHS session",ssn);

            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq))) {
                SCLogDebug("ssn %p: 4WHS wrong seq nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: 4WHS invalid ack nr on packet", ssn);
                StreamTcpSetEvent(p, STREAM_4WHS_INVALID_ACK);
                return -1;
            }

            SCLogDebug("4WHS normal pkt");
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));
            StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: ssn->client.next_win %" PRIu32 ", "
                    "ssn->client.last_ack %"PRIu32"", ssn,
                    ssn->client.next_win, ssn->client.last_ack);
            return 0;
        }

        bool ack_indicates_missed_3whs_ack_packet = false;
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
            } else if (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN) {
                SCLogDebug("ssn %p: ACK received on TFO session",ssn);
                /* fall through */

            } else {
                /* if we missed traffic between the S/SA and the current
                 * 'wrong direction' ACK, we could end up here. In IPS
                 * reject it. But in IDS mode we continue.
                 *
                 * IPS rejects as it should see all packets, so pktloss
                 * should lead to retransmissions. As this can also be
                 * pattern for MOTS/MITM injection attacks, we need to be
                 * careful.
                 */
                if (StreamTcpInlineMode()) {
                    if (p->payload_len > 0 &&
                            SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack) &&
                            SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                        /* packet loss is possible but unlikely here */
                        SCLogDebug("ssn %p: possible data injection", ssn);
                        StreamTcpSetEvent(p, STREAM_3WHS_ACK_DATA_INJECT);
                        return -1;
                    }

                    SCLogDebug("ssn %p: ACK received in the wrong direction",
                            ssn);
                    StreamTcpSetEvent(p, STREAM_3WHS_ACK_IN_WRONG_DIR);
                    return -1;
                }
                ack_indicates_missed_3whs_ack_packet = true;
            }
        }

        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ""
                ", ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                TCP_GET_ACK(p));

        /* Check both seq and ack number before accepting the packet and
           changing to ESTABLISHED state */
        if ((SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("normal pkt");

            /* process the packet normal, No Async streams :) */

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
            StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
                ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                ssn->server.next_win = ssn->server.last_ack +
                    ssn->server.window;
                if (!(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK)) {
                    /* window scaling for midstream pickups, we can't do much
                     * other than assume that it's set to the max value: 14 */
                    ssn->server.wscale = TCP_WSCALE_MAX;
                    ssn->client.wscale = TCP_WSCALE_MAX;
                    ssn->flags |= STREAMTCP_FLAG_SACKOK;
                }
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

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

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (ssn->flags & STREAMTCP_FLAG_MIDSTREAM) {
                ssn->server.window = TCP_GET_WINDOW(p);
                ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                /* window scaling for midstream pickups, we can't do much
                 * other than assume that it's set to the max value: 14 */
                ssn->server.wscale = TCP_WSCALE_MAX;
                ssn->client.wscale = TCP_WSCALE_MAX;
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            SCLogDebug("ssn %p: synrecv => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->server.next_seq %" PRIu32
                    , ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p)
                    + p->payload_len, ssn->server.next_seq);

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            /* Upon receiving the packet with correct seq number and wrong
               ACK number, it causes the other end to send RST. But some target
               system (Linux & solaris) does not RST the connection, so it is
               likely to avoid the detection */
        } else if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)){
            ssn->flags |= STREAMTCP_FLAG_DETECTION_EVASION_ATTEMPT;
            SCLogDebug("ssn %p: wrong ack nr on packet, possible evasion!!",
                    ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_RIGHT_SEQ_WRONG_ACK_EVASION);
            return -1;

            /* SYN/ACK followed by more TOCLIENT suggesting packet loss */
        } else if (PKT_IS_TOCLIENT(p) && !StreamTcpInlineMode() &&
                   SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) &&
                   SEQ_GT(TCP_GET_ACK(p), ssn->client.last_ack)) {
            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ACK for missing data: ssn->server.next_seq %u", ssn,
                    ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;

            ssn->client.window = TCP_GET_WINDOW(p);
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

            /* if we get a packet with a proper ack, but a seq that is beyond
             * next_seq but in-window, we probably missed some packets */
        } else if (SEQ_GT(TCP_GET_SEQ(p), ssn->client.next_seq) &&
                   SEQ_LEQ(TCP_GET_SEQ(p), ssn->client.next_win) &&
                   SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
            SCLogDebug("ssn %p: ACK for missing data", ssn);

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            SCLogDebug("ssn %p: ACK for missing data: ssn->client.next_seq %u", ssn, ssn->client.next_seq);
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
                ssn->flags |= STREAMTCP_FLAG_SACKOK;
            }

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

        /* toclient packet: after having missed the 3whs's final ACK */
        } else if ((ack_indicates_missed_3whs_ack_packet ||
                           (ssn->flags & STREAMTCP_FLAG_TCP_FAST_OPEN)) &&
                   SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack) &&
                   SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
            if (ack_indicates_missed_3whs_ack_packet) {
                SCLogDebug("ssn %p: packet fits perfectly after a missed 3whs-ACK", ssn);
            } else {
                SCLogDebug("ssn %p: (TFO) expected packet fits perfectly after SYN/ACK", ssn);
            }

            StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));

            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;

            StreamTcpPacketSetState(p, ssn, TCP_ESTABLISHED);
            SCLogDebug("ssn %p: =~ ssn state is now TCP_ESTABLISHED", ssn);

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

        } else {
            SCLogDebug("ssn %p: wrong seq nr on packet", ssn);

            StreamTcpSetEvent(p, STREAM_3WHS_WRONG_SEQ_WRONG_ACK);
            return -1;
        }

        SCLogDebug("ssn %p: ssn->server.next_win %" PRIu32 ", "
                "ssn->server.last_ack %"PRIu32"", ssn,
                ssn->server.next_win, ssn->server.last_ack);
    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the client to server. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembly.
 *
 *  Timestamp has already been checked at this point.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToServer(ThreadVars *tv, TcpSession *ssn, Packet *p,
                        StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
               "ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    const bool has_ack = (p->tcph->th_flags & TH_ACK) != 0;
    if (has_ack) {
        if ((ssn->flags & STREAMTCP_FLAG_ZWP_TC) && TCP_GET_ACK(p) == ssn->server.next_seq + 1) {
            SCLogDebug("ssn %p: accepting ACK as it ACKs the one byte from the ZWP", ssn);
            StreamTcpSetEvent(p, STREAM_EST_ACK_ZWP_DATA);

        } else if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
            return -1;
        }
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
            (TCP_GET_SEQ(p) == (ssn->client.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
            SCLogDebug("ssn %p: server => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    "%" PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* update the last_ack to current seq number as the session is
             * async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));

        } else if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {
            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ."
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :( */
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        } else if (SEQ_EQ(ssn->client.last_ack, (ssn->client.isn + 1)) &&
                (stream_config.async_oneside == TRUE) &&
                (ssn->flags & STREAMTCP_FLAG_MIDSTREAM)) {
            SCLogDebug("ssn %p: server => Asynchronous stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            /* it seems we missed SYN and SYN/ACK packets of this session.
             * Update the last_ack to current seq number as the session
             * is async and other stream is not updating it anymore :(*/
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_SEQ(p));
            ssn->flags |= STREAMTCP_FLAG_ASYNC;

        /* if last ack is beyond next_seq, we have accepted ack's for missing data.
         * In this case we do accept the data before last_ack if it is (partly)
         * beyond next seq */
        } else if (SEQ_GT(ssn->client.last_ack, ssn->client.next_seq) &&
                   SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->client.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %" PRIu32 " payload_len %" PRIu16
                       " before last_ack %" PRIu32 ", after next_seq %" PRIu32 ":"
                       " acked data that we haven't seen before",
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->client.last_ack,
                    ssn->client.next_seq);
        } else {
            SCLogDebug("ssn %p: server => SEQ before last_ack, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "), "
                    "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                    "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->client.last_ack, ssn->client.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->client.next_win);

            SCLogDebug("ssn %p: rejecting because pkt before last_ack", ssn);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->client.next_seq && ssn->client.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;
        ssn->flags |= STREAMTCP_FLAG_ZWP_TS;
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

    } else if (SEQ_GEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_seq)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
    }

    /* in window check */
    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
            (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                   "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        SCLogDebug("ssn %p: ssn->server.window %"PRIu32"", ssn,
                    ssn->server.window);

        /* Check if the ACK value is sane and inside the window limit */
        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));
        SCLogDebug("ack %u last_ack %u next_seq %u", TCP_GET_ACK(p), ssn->server.last_ack, ssn->server.next_seq);

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->server, p);

        /* update next_win */
        StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

        /* handle data (if any) */
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

    } else {
        SCLogDebug("ssn %p: toserver => SEQ out of window, packet SEQ "
                "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                "ssn->client.last_ack %" PRIu32 ", ssn->client.next_win "
                "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                ssn->client.last_ack, ssn->client.next_win,
                (TCP_GET_SEQ(p) + p->payload_len) - ssn->client.next_win);
        SCLogDebug("ssn %p: window %u sacked %u", ssn, ssn->client.window,
                StreamTcpSackedSize(&ssn->client));
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state packets, which are
 *          sent by the server to client. The function handles
 *          ACK packets and call StreamTcpReassembleHandleSegment() to handle
 *          the reassembly
 *
 *  Timestamp has already been checked at this point.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  ssn     Pointer to the current TCP session
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */
static int HandleEstablishedPacketToClient(ThreadVars *tv, TcpSession *ssn, Packet *p,
                        StreamTcpThread *stt, PacketQueueNoLock *pq)
{
    SCLogDebug("ssn %p: =+ pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ","
               " ACK %" PRIu32 ", WIN %"PRIu16"", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p), TCP_GET_WINDOW(p));

    const bool has_ack = (p->tcph->th_flags & TH_ACK) != 0;
    if (has_ack) {
        if ((ssn->flags & STREAMTCP_FLAG_ZWP_TS) && TCP_GET_ACK(p) == ssn->client.next_seq + 1) {
            SCLogDebug("ssn %p: accepting ACK as it ACKs the one byte from the ZWP", ssn);
            StreamTcpSetEvent(p, STREAM_EST_ACK_ZWP_DATA);

        } else if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_EST_INVALID_ACK);
            return -1;
        }
    }

    /* To get the server window value from the servers packet, when connection
       is picked up as midstream */
    if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
            (ssn->flags & STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED))
    {
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
        ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED;
        SCLogDebug("ssn %p: adjusted midstream ssn->server.next_win to "
                "%" PRIu32 "", ssn, ssn->server.next_win);
    }

    /* check for Keep Alive */
    if ((p->payload_len == 0 || p->payload_len == 1) &&
            (TCP_GET_SEQ(p) == (ssn->server.next_seq - 1))) {
        SCLogDebug("ssn %p: pkt is keep alive", ssn);

    /* normal pkt */
    } else if (!(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->server.last_ack))) {
        if (ssn->flags & STREAMTCP_FLAG_ASYNC) {

            SCLogDebug("ssn %p: client => Asynchrouns stream, packet SEQ"
                    " %" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                    " ssn->client.last_ack %" PRIu32 ", ssn->client.next_win"
                    " %"PRIu32"(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                    p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                    ssn->server.last_ack, ssn->server.next_win,
                    TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);

            ssn->server.last_ack = TCP_GET_SEQ(p);

        /* if last ack is beyond next_seq, we have accepted ack's for missing data.
         * In this case we do accept the data before last_ack if it is (partly)
         * beyond next seq */
        } else if (SEQ_GT(ssn->server.last_ack, ssn->server.next_seq) &&
                   SEQ_GT((TCP_GET_SEQ(p)+p->payload_len),ssn->server.next_seq))
        {
            SCLogDebug("ssn %p: PKT SEQ %" PRIu32 " payload_len %" PRIu16
                       " before last_ack %" PRIu32 ", after next_seq %" PRIu32 ":"
                       " acked data that we haven't seen before",
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack,
                    ssn->server.next_seq);
        } else {
            SCLogDebug("ssn %p: PKT SEQ %"PRIu32" payload_len %"PRIu16
                    " before last_ack %"PRIu32". next_seq %"PRIu32,
                    ssn, TCP_GET_SEQ(p), p->payload_len, ssn->server.last_ack, ssn->server.next_seq);
            StreamTcpSetEvent(p, STREAM_EST_PKT_BEFORE_LAST_ACK);
            return -1;
        }
    }

    int zerowindowprobe = 0;
    /* zero window probe */
    if (p->payload_len == 1 && TCP_GET_SEQ(p) == ssn->server.next_seq && ssn->server.window == 0) {
        SCLogDebug("ssn %p: zero window probe", ssn);
        zerowindowprobe = 1;
        ssn->flags |= STREAMTCP_FLAG_ZWP_TC;

        /* accept the segment */
        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

    } else if (SEQ_GEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_seq)) {
        StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
    }

    if (zerowindowprobe) {
        SCLogDebug("ssn %p: zero window probe, skipping oow check", ssn);
    } else if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
            (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
    {
        SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
        SCLogDebug("ssn %p: ssn->client.window %"PRIu32"", ssn,
                    ssn->client.window);

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        StreamTcpSackUpdatePacket(&ssn->client, p);

        StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);
    } else {
        SCLogDebug("ssn %p: client => SEQ out of window, packet SEQ"
                   "%" PRIu32 ", payload size %" PRIu32 " (%" PRIu32 "),"
                   " ssn->server.last_ack %" PRIu32 ", ssn->server.next_win "
                   "%" PRIu32 "(%"PRIu32")", ssn, TCP_GET_SEQ(p),
                   p->payload_len, TCP_GET_SEQ(p) + p->payload_len,
                   ssn->server.last_ack, ssn->server.next_win,
                   TCP_GET_SEQ(p) + p->payload_len - ssn->server.next_win);
        StreamTcpSetEvent(p, STREAM_EST_PACKET_OUT_OF_WINDOW);
        return -1;
    }
    return 0;
}

/**
 *  \internal
 *
 *  \brief Find the highest sequence number needed to consider all segments as ACK'd
 *
 *  Used to treat all segments as ACK'd upon receiving a valid RST.
 *
 *  \param stream stream to inspect the segments from
 *  \param seq sequence number to check against
 *
 *  \retval ack highest ack we need to set
 */
static inline uint32_t StreamTcpResetGetMaxAck(TcpStream *stream, uint32_t seq)
{
    uint32_t ack = seq;

    if (STREAM_HAS_SEEN_DATA(stream)) {
        const uint32_t tail_seq = STREAM_SEQ_RIGHT_EDGE(stream);
        if (SEQ_GT(tail_seq, ack)) {
            ack = tail_seq;
        }
    }

    SCReturnUInt(ack);
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state. The function handles the data inside packets and call
 *          StreamTcpReassembleHandleSegment(tv, ) to handle the reassembling.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        if (PKT_IS_TOSERVER(p)) {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_ACK(p);
            ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;
            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

            /* don't return packets to pools here just yet, the pseudo
             * packet will take care, otherwise the normal session
             * cleanup. */
        } else {
            StreamTcpCloseSsnWithReset(p, ssn);

            ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
            ssn->client.next_seq = TCP_GET_ACK(p);

            SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 "", ssn,
                    ssn->server.next_seq);
            ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);

            /* don't return packets to pools here just yet, the pseudo
             * packet will take care, otherwise the normal session
             * cleanup. */
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        SCLogDebug("ssn (%p: FIN received SEQ"
                " %" PRIu32 ", last ACK %" PRIu32 ", next win %"PRIu32","
                " win %" PRIu32 "", ssn, ssn->server.next_seq,
                ssn->client.last_ack, ssn->server.next_win,
                ssn->server.window);

        if ((StreamTcpHandleFin(tv, stt, ssn, p, pq)) == -1)
            return -1;

    /* SYN/ACK */
    } else if ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent",
                ssn);

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: SYN/ACK-pkt to server in ESTABLISHED state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_TOSERVER);
            return -1;
        }

        /* Check if the SYN/ACK packets ACK matches the earlier
         * received SYN/ACK packet. */
        if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack))) {
            SCLogDebug("ssn %p: ACK mismatch, packet ACK %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFFERENT_ACK);
            return -1;
        }

        /* Check if the SYN/ACK packet SEQ the earlier
         * received SYN packet. */
        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
            SCLogDebug("ssn %p: SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_ACK(p),
                    ssn->client.isn + 1);

            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND_WITH_DIFF_SEQ);
            return -1;
        }

        if (ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED) {
            /* a resend of a SYN while we are established already -- fishy */
            StreamTcpSetEvent(p, STREAM_EST_SYNACK_RESEND);
            return -1;
        }

        SCLogDebug("ssn %p: SYN/ACK packet on state ESTABLISHED... resent. "
                "Likely due server not receiving final ACK in 3whs", ssn);
        return 0;

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn %p: SYN packet on state ESTABLISHED... resent", ssn);
        if (PKT_IS_TOCLIENT(p)) {
            SCLogDebug("ssn %p: SYN-pkt to client in EST state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_TOCLIENT);
            return -1;
        }

        if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
            SCLogDebug("ssn %p: SYN with different SEQ on SYN_RECV state", ssn);

            StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND_DIFF_SEQ);
            return -1;
        }

        /* a resend of a SYN while we are established already -- fishy */
        StreamTcpSetEvent(p, STREAM_EST_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        /* Urgent pointer size can be more than the payload size, as it tells
         * the future coming data from the sender will be handled urgently
         * until data of size equal to urgent offset has been processed
         * (RFC 2147) */

        /* If the timestamp option is enabled for both the streams, then
         * validate the received packet timestamp value against the
         * stream->last_ts. If the timestamp is valid then process the
         * packet normally otherwise the drop the packet (RFC 1323) */
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            /* Process the received packet to server */
            HandleEstablishedPacketToServer(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->client.next_seq, ssn->server.last_ack
                    ,ssn->client.next_win, ssn->client.window);

        } else { /* implied to client */
            if (!(ssn->flags & STREAMTCP_FLAG_3WHS_CONFIRMED)) {
                ssn->flags |= STREAMTCP_FLAG_3WHS_CONFIRMED;
                SCLogDebug("3whs is now confirmed by server");
            }

            /* Process the received packet to client */
            HandleEstablishedPacketToClient(tv, ssn, p, stt, pq);

            SCLogDebug("ssn %p: next SEQ %" PRIu32 ", last ACK %" PRIu32 ","
                    " next win %" PRIu32 ", win %" PRIu32 "", ssn,
                    ssn->server.next_seq, ssn->client.last_ack,
                    ssn->server.next_win, ssn->server.window);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
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
 *
 *  \retval 0 success
 *  \retval -1 something wrong with the packet
 */

static int StreamTcpHandleFin(ThreadVars *tv, StreamTcpThread *stt,
                                TcpSession *ssn, Packet *p, PacketQueueNoLock *pq)
{
    if (PKT_IS_TOSERVER(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ %" PRIu32 ","
                " ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                TCP_GET_ACK(p));

        if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        const uint32_t pkt_re = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: -> SEQ %u, re %u. last_ack %u next_win %u", ssn, TCP_GET_SEQ(p), pkt_re,
                ssn->client.last_ack, ssn->client.next_win);
        if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.last_ack) &&
                SEQ_LEQ(pkt_re, ssn->client.next_win)) {
            // within expectations
        } else {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream", ssn, TCP_GET_SEQ(p),
                    ssn->client.next_seq);

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        if (p->tcph->th_flags & TH_SYN) {
            SCLogDebug("ssn %p: FIN+SYN", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_SYN);
            return -1;
        }
        StreamTcpPacketSetState(p, ssn, TCP_CLOSE_WAIT);
        SCLogDebug("ssn %p: state changed to TCP_CLOSE_WAIT", ssn);

        /* if we accept the FIN, next_seq needs to reflect the FIN */
        ssn->client.next_seq = TCP_GET_SEQ(p) + p->payload_len;

        SCLogDebug("ssn %p: ssn->client.next_seq %" PRIu32 "", ssn,
                    ssn->client.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
            ssn->server.next_seq = TCP_GET_ACK(p);

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->client, p, pq);

        SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK %" PRIu32 "",
                ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { /* implied to client */
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ %" PRIu32 ", "
                   "ACK %" PRIu32 "", ssn, p->payload_len, TCP_GET_SEQ(p),
                    TCP_GET_ACK(p));

        if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_FIN_INVALID_ACK);
            return -1;
        }

        const uint32_t pkt_re = TCP_GET_SEQ(p) + p->payload_len;
        SCLogDebug("ssn %p: -> SEQ %u, re %u. last_ack %u next_win %u", ssn, TCP_GET_SEQ(p), pkt_re,
                ssn->server.last_ack, ssn->server.next_win);
        if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.last_ack) &&
                SEQ_LEQ(pkt_re, ssn->server.next_win)) {
            // within expectations
        } else {
            SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 " != "
                    "%" PRIu32 " from stream (last_ack %u win %u = %u)", ssn, TCP_GET_SEQ(p),
                    ssn->server.next_seq, ssn->server.last_ack, ssn->server.window, (ssn->server.last_ack + ssn->server.window));

            StreamTcpSetEvent(p, STREAM_FIN_OUT_OF_WINDOW);
            return -1;
        }

        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT1);
        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT1", ssn);

        /* if we accept the FIN, next_seq needs to reflect the FIN */
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        SCLogDebug("ssn %p: ssn->server.next_seq %" PRIu32 " updated", ssn, ssn->server.next_seq);

        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            StreamTcpHandleTimestamp(ssn, p);
        }

        /* Update the next_seq, in case if we have missed the client packet
           and server has already received and acked it */
        if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
            ssn->client.next_seq = TCP_GET_ACK(p);

        if (p->tcph->th_flags & TH_ACK)
            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

        StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn, &ssn->server, p, pq);

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
 *
 *  \retval 0 success
 *  \retval -1 something wrong with the packet
 */

static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if ((p->tcph->th_flags & (TH_FIN|TH_ACK)) == (TH_FIN|TH_ACK)) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq - 1) ||
                       SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window))) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq - 1, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (SEQ_EQ(ssn->server.next_seq - 1, TCP_GET_SEQ(p)) &&
                       SEQ_EQ(ssn->client.last_ack, TCP_GET_ACK(p))) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq - 1) ||
                       SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                /* Update the next_seq, in case if we have missed the client
                   packet and server has already received and acked it */
                if (SEQ_LT(ssn->client.next_seq - 1, TCP_GET_ACK(p)))
                    ssn->client.next_seq = TCP_GET_ACK(p);

                if (SEQ_EQ(ssn->server.next_seq - 1, TCP_GET_SEQ(p))) {
                    StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
                }

                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq - 1) ||
                       SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window))) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq - 1, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq - 1, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq - 1) ||
                       SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN1_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSING);
                SCLogDebug("ssn %p: state changed to TCP_CLOSING", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq - 1, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq - 1, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
            }

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait1", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (SEQ_LT(TCP_GET_ACK(p), ssn->server.next_seq)) {
                SCLogDebug("ssn %p: ACK's older segment as %u < %u", ssn, TCP_GET_ACK(p),
                        ssn->server.next_seq);
            } else if (!retransmission) {
                if (SEQ_EQ(TCP_GET_ACK(p), ssn->server.next_seq)) {
                    if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
                            (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM | STREAMTCP_FLAG_ASYNC))) {
                        SCLogDebug("ssn %p: seq %" PRIu32 " in window, ssn->client.next_win "
                                   "%" PRIu32 "",
                                ssn, TCP_GET_SEQ(p), ssn->client.next_win);
                        SCLogDebug(
                                "seq %u client.next_seq %u", TCP_GET_SEQ(p), ssn->client.next_seq);
                        if (TCP_GET_SEQ(p) == ssn->client.next_seq) {
                            StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                            SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                        }
                    } else {
                        SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                                   " != %" PRIu32 " from stream",
                                ssn, TCP_GET_SEQ(p), ssn->client.next_seq);

                        StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                        return -1;
                    }

                    ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
                }
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq - 1, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (TCP_GET_SEQ(p) + p->payload_len));
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpSackUpdatePacket(&ssn->server, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);

        } else { /* implied to client */

            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN1_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
                        (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);

                    if (TCP_GET_SEQ(p) == ssn->server.next_seq - 1) {
                        StreamTcpPacketSetState(p, ssn, TCP_FIN_WAIT2);
                        SCLogDebug("ssn %p: state changed to TCP_FIN_WAIT2", ssn);
                    }
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN1_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq - 1, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(ssn->server.next_seq - 1, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (TCP_GET_SEQ(p) + p->payload_len));
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn (%p): default case", ssn);
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
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->server.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    StreamTcpUpdateNextSeq(
                            ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
                }
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq - 1) &&
                SEQ_EQ(TCP_GET_ACK(p), ssn->client.last_ack)) {
                SCLogDebug("ssn %p: retransmission", ssn);
                retransmission = 1;
            } else if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                    SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ "
                        "%" PRIu32 " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_FIN2_FIN_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on FinWait2", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win) ||
                        (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->client.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->client.next_win);

                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));
            }

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpSackUpdatePacket(&ssn->server, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->server, (ssn->server.last_ack + ssn->server.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;

            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_FIN2_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                if (SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win) ||
                        (ssn->flags & (STREAMTCP_FLAG_MIDSTREAM|STREAMTCP_FLAG_ASYNC)))
                {
                    SCLogDebug("ssn %p: seq %"PRIu32" in window, ssn->server.next_win "
                            "%" PRIu32 "", ssn, TCP_GET_SEQ(p), ssn->server.next_win);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_FIN2_ACK_WRONG_SEQ);
                    return -1;
                }

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));
            }

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpSackUpdatePacket(&ssn->client, p);

            /* update next_win */
            StreamTcpUpdateNextWin(ssn, &ssn->client, (ssn->client.last_ack + ssn->client.window));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
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
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on Closing", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }
            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else { /* implied to client */
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSING_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSING_INVALID_ACK);
                return -1;
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_TIME_WAIT);
                SCLogDebug("ssn %p: state changed to TCP_TIME_WAIT", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);

            SCLogDebug("StreamTcpPacketStateClosing (%p): =+ next SEQ "
                    "%" PRIu32 ", last ACK %" PRIu32 "", ssn,
                    ssn->server.next_seq, ssn->client.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
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
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    SCEnter();

    if (ssn == NULL) {
        SCReturnInt(-1);
    }

    if (PKT_IS_TOCLIENT(p)) {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p));
    } else {
        SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                TCP_GET_SEQ(p), TCP_GET_ACK(p));
    }

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);
                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            /* don't update to LAST_ACK here as we want a toclient FIN for that */

            if (!retransmission)
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);

            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) ||
                        SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
                {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_CLOSEWAIT_FIN_OUT_OF_WINDOW);
                    SCReturnInt(-1);
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_LAST_ACK);
                SCLogDebug("ssn %p: state changed to TCP_LAST_ACK", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (p->tcph->th_flags & TH_ACK)
                StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on CloseWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        SCReturnInt(-1);

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                SCReturnInt(-1);
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->client.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->client.next_seq))
                StreamTcpUpdateNextSeq(ssn, &ssn->client, (ssn->client.next_seq + p->payload_len));

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (p->payload_len > 0 && (SEQ_LEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack))) {
                SCLogDebug("ssn %p: -> retransmission", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_PKT_BEFORE_LAST_ACK);
                SCReturnInt(-1);

            } else if (SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window)))
            {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->server.next_seq);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_ACK_OUT_OF_WINDOW);
                SCReturnInt(-1);
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_CLOSEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            if (SEQ_EQ(TCP_GET_SEQ(p),ssn->server.next_seq))
                StreamTcpUpdateNextSeq(ssn, &ssn->server, (ssn->server.next_seq + p->payload_len));

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
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

static int StreamTcpPacketStateLastAck(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */
        SCLogDebug("ssn (%p): FIN pkt on LastAck", ssn);

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on LastAck", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));

            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_LASTACK_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    SCLogDebug("ssn %p: not updating state as packet is before next_seq", ssn);
                } else if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq + 1) {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->client.next_seq);
                    StreamTcpSetEvent(p, STREAM_LASTACK_ACK_WRONG_SEQ);
                    return -1;
                } else {
                    StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                    SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                }
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        }
    } else {
        SCLogDebug("ssn %p: default case", ssn);
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
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        if (!StreamTcpValidateRst(ssn, p))
            return -1;

        StreamTcpCloseSsnWithReset(p, ssn);

        if (PKT_IS_TOSERVER(p)) {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->server, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->server,
                        StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->client,
                    StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
        } else {
            if ((p->tcph->th_flags & TH_ACK) && StreamTcpValidateAck(ssn, &ssn->client, p) == 0)
                StreamTcpUpdateLastAck(ssn, &ssn->client,
                        StreamTcpResetGetMaxAck(&ssn->client, TCP_GET_ACK(p)));

            StreamTcpUpdateLastAck(ssn, &ssn->server,
                    StreamTcpResetGetMaxAck(&ssn->server, TCP_GET_SEQ(p)));

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
        }

    } else if (p->tcph->th_flags & TH_FIN) {
        /** \todo */

    } else if (p->tcph->th_flags & TH_SYN) {
        SCLogDebug("ssn (%p): SYN pkt on TimeWait", ssn);
        StreamTcpSetEvent(p, STREAM_SHUTDOWN_SYN_RESEND);
        return -1;

    } else if (p->tcph->th_flags & TH_ACK) {
        if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
            if (!StreamTcpValidateTimestamp(ssn, p))
                return -1;
        }

        if (PKT_IS_TOSERVER(p)) {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to server: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->client, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;

            } else if (TCP_GET_SEQ(p) != ssn->client.next_seq && TCP_GET_SEQ(p) != ssn->client.next_seq+1) {
                SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                        " != %" PRIu32 " from stream", ssn,
                        TCP_GET_SEQ(p), ssn->client.next_seq);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                return -1;
            }

            if (StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->server.next_seq, TCP_GET_ACK(p)))
                ssn->server.next_seq = TCP_GET_ACK(p);

            StreamTcpUpdateLastAck(ssn, &ssn->server, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->client, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->client.next_seq,
                    ssn->server.last_ack);
        } else {
            SCLogDebug("ssn %p: pkt (%" PRIu32 ") is to client: SEQ "
                    "%" PRIu32 ", ACK %" PRIu32 "", ssn, p->payload_len,
                    TCP_GET_SEQ(p), TCP_GET_ACK(p));
            int retransmission = 0;
            if (StreamTcpPacketIsRetransmission(&ssn->server, p)) {
                SCLogDebug("ssn %p: packet is retransmission", ssn);
                retransmission = 1;
            } else if (TCP_GET_SEQ(p) != ssn->server.next_seq - 1 &&
                       TCP_GET_SEQ(p) != ssn->server.next_seq) {
                if (p->payload_len > 0 && TCP_GET_SEQ(p) == ssn->server.last_ack) {
                    SCLogDebug("ssn %p: -> retransmission", ssn);
                    SCReturnInt(0);
                } else {
                    SCLogDebug("ssn %p: -> SEQ mismatch, packet SEQ %" PRIu32 ""
                            " != %" PRIu32 " from stream", ssn,
                            TCP_GET_SEQ(p), ssn->server.next_seq);
                    StreamTcpSetEvent(p, STREAM_TIMEWAIT_ACK_WRONG_SEQ);
                    return -1;
                }
            }

            if (StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
                SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
                StreamTcpSetEvent(p, STREAM_TIMEWAIT_INVALID_ACK);
                SCReturnInt(-1);
            }

            if (!retransmission) {
                StreamTcpPacketSetState(p, ssn, TCP_CLOSED);
                SCLogDebug("ssn %p: state changed to TCP_CLOSED", ssn);

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;
            }

            if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
                StreamTcpHandleTimestamp(ssn, p);
            }

            /* Update the next_seq, in case if we have missed the client
               packet and server has already received and acked it */
            if (SEQ_LT(ssn->client.next_seq, TCP_GET_ACK(p)))
                ssn->client.next_seq = TCP_GET_ACK(p);

            StreamTcpUpdateLastAck(ssn, &ssn->client, TCP_GET_ACK(p));

            StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                    &ssn->server, p, pq);
            SCLogDebug("ssn %p: =+ next SEQ %" PRIu32 ", last ACK "
                    "%" PRIu32 "", ssn, ssn->server.next_seq,
                    ssn->client.last_ack);
        }

    } else {
        SCLogDebug("ssn %p: default case", ssn);
    }

    return 0;
}

static int StreamTcpPacketStateClosed(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq)
{
    if (ssn == NULL)
        return -1;

    if (p->tcph->th_flags & TH_RST) {
        SCLogDebug("RST on closed state");
        return 0;
    }

    TcpStream *stream = NULL, *ostream = NULL;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    SCLogDebug("stream %s ostream %s",
            stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV?"true":"false",
            ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV ? "true":"false");

    /* if we've seen a RST on our direction, but not on the other
     * see if we perhaps need to continue processing anyway. */
    if ((stream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) == 0) {
        if (ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) {
            if (StreamTcpStateDispatch(tv, p, stt, ssn, &stt->pseudo_queue, ssn->pstate) < 0)
                return -1;
            /* if state is still "closed", it wasn't updated by our dispatch. */
            if (ssn->state == TCP_CLOSED)
                ssn->state = ssn->pstate;
        }
    }
    return 0;
}

static void StreamTcpPacketCheckPostRst(TcpSession *ssn, Packet *p)
{
    if (p->flags & PKT_PSEUDO_STREAM_END) {
        return;
    }
    /* more RSTs are not unusual */
    if ((p->tcph->th_flags & (TH_RST)) != 0) {
        return;
    }

    TcpStream *ostream = NULL;
    if (PKT_IS_TOSERVER(p)) {
        ostream = &ssn->server;
    } else {
        ostream = &ssn->client;
    }

    if (ostream->flags & STREAMTCP_STREAM_FLAG_RST_RECV) {
        SCLogDebug("regular packet %"PRIu64" from same sender as "
                "the previous RST. Looks like it injected!", p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_RST_RECV;
        ssn->flags &= ~STREAMTCP_FLAG_CLOSED_BY_RST;
        StreamTcpSetEvent(p, STREAM_SUSPECTED_RST_INJECT);
        return;
    }
    return;
}

/**
 *  \retval 1 packet is a keep alive pkt
 *  \retval 0 packet is not a keep alive pkt
 */
static int StreamTcpPacketIsKeepAlive(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    /*
       rfc 1122:
       An implementation SHOULD send a keep-alive segment with no
       data; however, it MAY be configurable to send a keep-alive
       segment containing one garbage octet, for compatibility with
       erroneous TCP implementations.
     */
    if (p->payload_len > 1)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0) {
        return 0;
    }

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    if (ack == ostream->last_ack && seq == (stream->next_seq - 1)) {
        SCLogDebug("packet is TCP keep-alive: %"PRIu64, p->pcap_cnt);
        stream->flags |= STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq,  (stream->next_seq - 1), ack, ostream->last_ack);
    return 0;
}

/**
 *  \retval 1 packet is a keep alive ACK pkt
 *  \retval 0 packet is not a keep alive ACK pkt
 */
static int StreamTcpPacketIsKeepAliveACK(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    /* should get a normal ACK to a Keep Alive */
    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win != ostream->window)
        return 0;

    if ((ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) && ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP keep-aliveACK: %"PRIu64, p->pcap_cnt);
        ostream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u) FLAG_KEEPALIVE: %s", seq, stream->next_seq, ack, ostream->last_ack,
            ostream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE ? "set" : "not set");
    return 0;
}

static void StreamTcpClearKeepAliveFlag(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    if (stream->flags & STREAMTCP_STREAM_FLAG_KEEPALIVE) {
        stream->flags &= ~STREAMTCP_STREAM_FLAG_KEEPALIVE;
        SCLogDebug("FLAG_KEEPALIVE cleared");
    }
}

/**
 *  \retval 1 packet is a window update pkt
 *  \retval 0 packet is not a window update pkt
 */
static int StreamTcpPacketIsWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED)
        return 0;

    if (p->payload_len > 0)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (TCP_GET_WINDOW(p) == 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;
    if (pkt_win == ostream->window)
        return 0;

    if (ack == ostream->last_ack && seq == stream->next_seq) {
        SCLogDebug("packet is TCP window update: %"PRIu64, p->pcap_cnt);
        return 1;
    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/**
 *  Try to detect whether a packet is a valid FIN 4whs final ack.
 *
 */
static int StreamTcpPacketIsFinShutdownAck(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;
    if (!(ssn->state == TCP_TIME_WAIT || ssn->state == TCP_CLOSE_WAIT || ssn->state == TCP_LAST_ACK))
        return 0;
    if (p->tcph->th_flags != TH_ACK)
        return 0;
    if (p->payload_len != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    SCLogDebug("%"PRIu64", seq %u ack %u stream->next_seq %u ostream->next_seq %u",
            p->pcap_cnt, seq, ack, stream->next_seq, ostream->next_seq);

    if (SEQ_EQ(stream->next_seq + 1, seq) && SEQ_EQ(ack, ostream->next_seq + 1)) {
        return 1;
    }
    return 0;
}

/**
 *  Try to detect packets doing bad window updates
 *
 *  See bug 1238.
 *
 *  Find packets that are unexpected, and shrink the window to the point
 *  where the packets we do expect are rejected for being out of window.
 *
 *  The logic we use here is:
 *  - packet seq > next_seq
 *  - packet ack > next_seq (packet acks unseen data)
 *  - packet shrinks window more than it's own data size
 *  - packet shrinks window more than the diff between it's ack and the
 *    last_ack value
 *
 *  Packets coming in after packet loss can look quite a bit like this.
 */
static int StreamTcpPacketIsBadWindowUpdate(TcpSession *ssn, Packet *p)
{
    TcpStream *stream = NULL, *ostream = NULL;
    uint32_t seq;
    uint32_t ack;
    uint32_t pkt_win;

    if (p->flags & PKT_PSEUDO_STREAM_END)
        return 0;

    if (ssn->state < TCP_ESTABLISHED || ssn->state == TCP_CLOSED)
        return 0;

    if ((p->tcph->th_flags & (TH_SYN|TH_FIN|TH_RST)) != 0)
        return 0;

    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        ostream = &ssn->server;
    } else {
        stream = &ssn->server;
        ostream = &ssn->client;
    }

    seq = TCP_GET_SEQ(p);
    ack = TCP_GET_ACK(p);

    pkt_win = TCP_GET_WINDOW(p) << ostream->wscale;

    if (pkt_win < ostream->window) {
        uint32_t diff = ostream->window - pkt_win;
        if (diff > p->payload_len &&
                SEQ_GT(ack, ostream->next_seq) &&
                SEQ_GT(seq, stream->next_seq))
        {
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u, diff %u, dsize %u",
                p->pcap_cnt, pkt_win, ostream->window, diff, p->payload_len);
            SCLogDebug("%"PRIu64", pkt_win %u, stream win %u",
                p->pcap_cnt, pkt_win, ostream->window);
            SCLogDebug("%"PRIu64", seq %u ack %u ostream->next_seq %u ostream->last_ack %u, ostream->next_win %u, diff %u (%u)",
                    p->pcap_cnt, seq, ack, ostream->next_seq, ostream->last_ack, ostream->next_win,
                    ostream->next_seq - ostream->last_ack, stream->next_seq - stream->last_ack);

            /* get the expected window shrinking from looking at ack vs last_ack.
             * Observed a lot of just a little overrunning that value. So added some
             * margin that is still ok. To make sure this isn't a loophole to still
             * close the window, this is limited to windows above 1024. Both values
             * are rather arbitrary. */
            uint32_t adiff = ack - ostream->last_ack;
            if (((pkt_win > 1024) && (diff > (adiff + 32))) ||
                ((pkt_win <= 1024) && (diff > adiff)))
            {
                SCLogDebug("pkt ACK %u is %u bytes beyond last_ack %u, shrinks window by %u "
                        "(allowing 32 bytes extra): pkt WIN %u", ack, adiff, ostream->last_ack, diff, pkt_win);
                SCLogDebug("%u - %u = %u (state %u)", diff, adiff, diff - adiff, ssn->state);
                StreamTcpSetEvent(p, STREAM_PKT_BAD_WINDOW_UPDATE);
                return 1;
            }
        }

    }
    SCLogDebug("seq %u (%u), ack %u (%u)", seq, stream->next_seq, ack, ostream->last_ack);
    return 0;
}

/** \internal
 *  \brief call packet handling function for 'state'
 *  \param state current TCP state
 */
static inline int StreamTcpStateDispatch(ThreadVars *tv, Packet *p,
        StreamTcpThread *stt, TcpSession *ssn, PacketQueueNoLock *pq,
        const uint8_t state)
{
    SCLogDebug("ssn: %p", ssn);
    switch (state) {
        case TCP_SYN_SENT:
            if (StreamTcpPacketStateSynSent(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_SYN_RECV:
            if (StreamTcpPacketStateSynRecv(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_ESTABLISHED:
            if (StreamTcpPacketStateEstablished(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_FIN_WAIT1:
            SCLogDebug("packet received on TCP_FIN_WAIT1 state");
            if (StreamTcpPacketStateFinWait1(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_FIN_WAIT2:
            SCLogDebug("packet received on TCP_FIN_WAIT2 state");
            if (StreamTcpPacketStateFinWait2(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSING:
            SCLogDebug("packet received on TCP_CLOSING state");
            if (StreamTcpPacketStateClosing(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSE_WAIT:
            SCLogDebug("packet received on TCP_CLOSE_WAIT state");
            if (StreamTcpPacketStateCloseWait(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_LAST_ACK:
            SCLogDebug("packet received on TCP_LAST_ACK state");
            if (StreamTcpPacketStateLastAck(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_TIME_WAIT:
            SCLogDebug("packet received on TCP_TIME_WAIT state");
            if (StreamTcpPacketStateTimeWait(tv, p, stt, ssn, pq)) {
                return -1;
            }
            break;
        case TCP_CLOSED:
            /* TCP session memory is not returned to pool until timeout. */
            SCLogDebug("packet received on closed state");

            if (StreamTcpPacketStateClosed(tv, p, stt, ssn, pq)) {
                return -1;
            }

            break;
        default:
            SCLogDebug("packet received on default state");
            break;
    }
    return 0;
}

static inline void HandleThreadId(ThreadVars *tv, Packet *p, StreamTcpThread *stt)
{
    const int idx = (!(PKT_IS_TOSERVER(p)));

    /* assign the thread id to the flow */
    if (unlikely(p->flow->thread_id[idx] == 0)) {
        p->flow->thread_id[idx] = (FlowThreadId)tv->id;
    } else if (unlikely((FlowThreadId)tv->id != p->flow->thread_id[idx])) {
        SCLogDebug("wrong thread: flow has %u, we are %d", p->flow->thread_id[idx], tv->id);
        if (p->pkt_src == PKT_SRC_WIRE) {
            StatsIncr(tv, stt->counter_tcp_wrong_thread);
            if ((p->flow->flags & FLOW_WRONG_THREAD) == 0) {
                p->flow->flags |= FLOW_WRONG_THREAD;
                StreamTcpSetEvent(p, STREAM_WRONG_THREAD);
            }
        }
    }
}

/* flow is and stays locked */
int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt,
                     PacketQueueNoLock *pq)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;

    /* track TCP flags */
    if (ssn != NULL) {
        ssn->tcp_packet_flags |= p->tcph->th_flags;
        if (PKT_IS_TOSERVER(p)) {
            ssn->client.tcp_flags |= p->tcph->th_flags;
            if (unlikely(ssn->client.tcp_init_flags == 0)) {
                /* This is the first to-server packet in the flow to be seen by
                 * suricata. Set tcp_init_flags flags.
                 */
                ssn->client.tcp_init_flags = p->tcph->th_flags;
            } else if (unlikely(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn))) {
                /* This is the first to-server packet in the flow, but not the first to
                 * be seen by suricata. This can happen when the ACK in the 3-way
                 * handshake is seen before the SYN. Update tcp_init_flags flags.
                 */
                ssn->client.tcp_init_flags = p->tcph->th_flags;
            }
        } else if (PKT_IS_TOCLIENT(p)) {
            ssn->server.tcp_flags |= p->tcph->th_flags;
            if (unlikely(ssn->server.tcp_init_flags == 0)) {
                /* This is the first to-client packet in the flow to be seen by
                 * suricata. Set tcp_init_flags flags.
                 */
                ssn->server.tcp_init_flags = p->tcph->th_flags;
            } else if (unlikely(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.isn))) {
                /* This is the first to-client packet in the flow, but not the first to
                 * be seen by suricata. Update tcp_init_flags flags.
                 */
                ssn->server.tcp_init_flags = p->tcph->th_flags;
            }
        }

        /* If the first packets in both directions have now been seen in what was
         * previously considered a midstream-pickup, then the STREAMTCP_FLAG_MIDSTREAM
         * flag can be cleared
         */
        if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
                ((ssn->server.tcp_init_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) &&
                ((ssn->client.tcp_init_flags & TH_SYN) == TH_SYN)) {
            SCLogDebug("ssn %p: removing MIDSTREAM flag as 1st packets have been seen on both sides", ssn);
            ssn->flags &= ~STREAMTCP_FLAG_MIDSTREAM;
        }

        /* check if we need to unset the ASYNC flag */
        if (ssn->flags & STREAMTCP_FLAG_ASYNC &&
            ssn->client.tcp_flags != 0 &&
            ssn->server.tcp_flags != 0)
        {
            SCLogDebug("ssn %p: removing ASYNC flag as we have packets on both sides", ssn);
            ssn->flags &= ~STREAMTCP_FLAG_ASYNC;
        }
    }

    /* broken TCP http://ask.wireshark.org/questions/3183/acknowledgment-number-broken-tcp-the-acknowledge-field-is-nonzero-while-the-ack-flag-is-not-set */
    if (!(p->tcph->th_flags & TH_ACK) && TCP_GET_ACK(p) != 0) {
        StreamTcpSetEvent(p, STREAM_PKT_BROKEN_ACK);
        if (!(p->tcph->th_flags & TH_SYN))
            goto error;
    }

    /* If we are on IPS mode, and got a drop action triggered from
     * the IP only module, or from a reassembled msg and/or from an
     * applayer detection, then drop the rest of the packets of the
     * same stream and avoid inspecting it any further */
    if (StreamTcpCheckFlowDrops(p) == 1) {
        DEBUG_VALIDATE_BUG_ON(!(PKT_IS_PSEUDOPKT(p)) && !PACKET_TEST_ACTION(p, ACTION_DROP));
        SCLogDebug("flow triggered a drop rule");
        StreamTcpDisableAppLayer(p->flow);
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p);
        SCReturnInt(0);
    }

    if (ssn == NULL || ssn->state == TCP_NONE) {
        if (StreamTcpPacketStateNone(tv, p, stt, ssn, &stt->pseudo_queue) == -1) {
            goto error;
        }

        if (ssn != NULL)
            SCLogDebug("ssn->alproto %"PRIu16"", p->flow->alproto);
    } else {
        /* special case for PKT_PSEUDO_STREAM_END packets:
         * bypass the state handling and various packet checks,
         * we care about reassembly here. */
        if (p->flags & PKT_PSEUDO_STREAM_END) {
            if (PKT_IS_TOCLIENT(p)) {
                ssn->client.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                        &ssn->server, p, pq);
            } else {
                ssn->server.last_ack = TCP_GET_ACK(p);
                StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                        &ssn->client, p, pq);
            }
            /* straight to 'skip' as we already handled reassembly */
            goto skip;
        }

        if (p->flow->flags & FLOW_WRONG_THREAD) {
            /* Stream and/or session in known bad condition. Block events
             * from being set. */
            p->flags |= PKT_STREAM_NO_EVENTS;
        }

        if (StreamTcpPacketIsKeepAlive(ssn, p) == 1) {
            goto skip;
        }
        if (StreamTcpPacketIsKeepAliveACK(ssn, p) == 1) {
            StreamTcpClearKeepAliveFlag(ssn, p);
            goto skip;
        }
        StreamTcpClearKeepAliveFlag(ssn, p);

        /* if packet is not a valid window update, check if it is perhaps
         * a bad window update that we should ignore (and alert on) */
        if (StreamTcpPacketIsFinShutdownAck(ssn, p) == 0)
            if (StreamTcpPacketIsWindowUpdate(ssn, p) == 0)
                if (StreamTcpPacketIsBadWindowUpdate(ssn,p))
                    goto skip;

        /* handle the per 'state' logic */
        if (StreamTcpStateDispatch(tv, p, stt, ssn, &stt->pseudo_queue, ssn->state) < 0)
            goto error;

    skip:
        StreamTcpPacketCheckPostRst(ssn, p);

        if (ssn->state >= TCP_ESTABLISHED) {
            p->flags |= PKT_STREAM_EST;
        }
    }

    /* deal with a pseudo packet that is created upon receiving a RST
     * segment. To be sure we process both sides of the connection, we
     * inject a fake packet into the system, forcing reassembly of the
     * opposing direction.
     * There should be only one, but to be sure we do a while loop. */
    if (ssn != NULL) {
        while (stt->pseudo_queue.len > 0) {
            SCLogDebug("processing pseudo packet / stream end");
            Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
            if (np != NULL) {
                /* process the opposing direction of the original packet */
                if (PKT_IS_TOSERVER(np)) {
                    SCLogDebug("pseudo packet is to server");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                            &ssn->client, np, NULL);
                } else {
                    SCLogDebug("pseudo packet is to client");
                    StreamTcpReassembleHandleSegment(tv, stt->ra_ctx, ssn,
                            &ssn->server, np, NULL);
                }

                /* enqueue this packet so we inspect it in detect etc */
                PacketEnqueueNoLock(pq, np);
            }
            SCLogDebug("processing pseudo packet / stream end done");
        }

        /* recalc the csum on the packet if it was modified */
        if (p->flags & PKT_STREAM_MODIFIED) {
            ReCalculateChecksum(p);
        }
        /* check for conditions that may make us not want to log this packet */

        /* streams that hit depth */
        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) ||
             (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            /* we can call bypass callback, if enabled */
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }
        }

        if ((ssn->client.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) ||
             (ssn->server.flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        /* encrypted packets */
        if ((PKT_IS_TOSERVER(p) && (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) ||
            (PKT_IS_TOCLIENT(p) && (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)))
        {
            p->flags |= PKT_STREAM_NOPCAPLOG;
        }

        if (ssn->flags & STREAMTCP_FLAG_BYPASS) {
            /* we can call bypass callback, if enabled */
            if (StreamTcpBypassEnabled()) {
                PacketBypassCallback(p);
            }

        /* if stream is dead and we have no detect engine at all, bypass. */
        } else if (g_detect_disabled &&
                (ssn->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
                (ssn->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
                StreamTcpBypassEnabled())
        {
            SCLogDebug("bypass as stream is dead and we have no rules");
            PacketBypassCallback(p);
        }
    }

    SCReturnInt(0);

error:
    /* make sure we don't leave packets in our pseudo queue */
    while (stt->pseudo_queue.len > 0) {
        Packet *np = PacketDequeueNoLock(&stt->pseudo_queue);
        if (np != NULL) {
            PacketEnqueueNoLock(pq, np);
        }
    }

    /* recalc the csum on the packet if it was modified */
    if (p->flags & PKT_STREAM_MODIFIED) {
        ReCalculateChecksum(p);
    }

    if (StreamTcpInlineDropInvalid()) {
        /* disable payload inspection as we're dropping this packet
         * anyway. Doesn't disable all detection, so we can still
         * match on the stream event that was set. */
        DecodeSetNoPayloadInspectionFlag(p);
        PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_STREAM_ERROR);
    }
    SCReturnInt(-1);
}

/**
 *  \brief  Function to validate the checksum of the received packet. If the
 *          checksum is invalid, packet will be dropped, as the end system will
 *          also drop the packet.
 *
 *  \param  p       Packet of which checksum has to be validated
 *  \retval  1 if the checksum is valid, otherwise 0
 */
static inline int StreamTcpValidateChecksum(Packet *p)
{
    int ret = 1;

    if (p->flags & PKT_IGNORE_CHECKSUM)
        return ret;

    if (p->level4_comp_csum == -1) {
        if (PKT_IS_IPV4(p)) {
            p->level4_comp_csum = TCPChecksum(p->ip4h->s_ip_addrs,
                                              (uint16_t *)p->tcph,
                                              (p->payload_len +
                                                  TCP_GET_HLEN(p)),
                                              p->tcph->th_sum);
        } else if (PKT_IS_IPV6(p)) {
            p->level4_comp_csum = TCPV6Checksum(p->ip6h->s_ip6_addrs,
                                                (uint16_t *)p->tcph,
                                                (p->payload_len +
                                                    TCP_GET_HLEN(p)),
                                                p->tcph->th_sum);
        }
    }

    if (p->level4_comp_csum != 0) {
        ret = 0;
        if (p->livedev) {
            (void) SC_ATOMIC_ADD(p->livedev->invalid_checksums, 1);
        } else if (p->pcap_cnt) {
            PcapIncreaseInvalidChecksum();
        }
    }

    return ret;
}

/** \internal
 *  \brief check if a packet is a valid stream started
 *  \retval bool true/false */
static int TcpSessionPacketIsStreamStarter(const Packet *p)
{
    if (p->tcph->th_flags & (TH_RST | TH_FIN)) {
        return 0;
    }

    if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
        SCLogDebug("packet %"PRIu64" is a stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
        return 1;
    }

    if (stream_config.midstream == TRUE || stream_config.async_oneside == TRUE) {
        if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            SCLogDebug("packet %"PRIu64" is a midstream stream starter: %02x", p->pcap_cnt, p->tcph->th_flags);
            return 1;
        }
    }
    return 0;
}

/** \internal
 *  \brief Check if Flow and TCP SSN allow this flow/tuple to be reused
 *  \retval bool true yes reuse, false no keep tracking old ssn */
static int TcpSessionReuseDoneEnoughSyn(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOSERVER) {
        if (ssn == NULL) {
            /* most likely a flow that was picked up after the 3whs, or a flow that
             * does not have a session due to memcap issues. */
            SCLogDebug("steam starter packet %" PRIu64 ", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (SEQ_EQ(ssn->client.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}

/** \internal
 *  \brief check if ssn is done enough for reuse by syn/ack
 *  \note should only be called if midstream is enabled
 */
static int TcpSessionReuseDoneEnoughSynAck(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if (FlowGetPacketDirection(f, p) == TOCLIENT) {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. No reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (SEQ_EQ(ssn->server.isn, TCP_GET_SEQ(p))) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p. Packet SEQ == Stream ISN. Retransmission. Don't reuse.", p->pcap_cnt, ssn);
            return 0;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }

    } else {
        if (ssn == NULL) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p null. Reuse.", p->pcap_cnt, ssn);
            return 1;
        }
        if (ssn->state >= TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state >= TCP_LAST_ACK (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state == TCP_NONE) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state == TCP_NONE (%u). Reuse.", p->pcap_cnt, ssn, ssn->state);
            return 1;
        }
        if (ssn->state < TCP_LAST_ACK) {
            SCLogDebug("steam starter packet %"PRIu64", ssn %p state < TCP_LAST_ACK (%u). Don't reuse.", p->pcap_cnt, ssn, ssn->state);
            return 0;
        }
    }

    SCLogDebug("default: how did we get here?");
    return 0;
}

/** \brief Check if SSN is done enough for reuse
 *
 *  Reuse means a new TCP session reuses the tuple (flow in suri)
 *
 *  \retval bool true if ssn can be reused, false if not */
static int TcpSessionReuseDoneEnough(const Packet *p, const Flow *f, const TcpSession *ssn)
{
    if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
        return TcpSessionReuseDoneEnoughSyn(p, f, ssn);
    }

    if (stream_config.midstream == TRUE || stream_config.async_oneside == TRUE) {
        if ((p->tcph->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            return TcpSessionReuseDoneEnoughSynAck(p, f, ssn);
        }
    }

    return 0;
}

int TcpSessionPacketSsnReuse(const Packet *p, const Flow *f, const void *tcp_ssn)
{
    if (p->proto == IPPROTO_TCP && p->tcph != NULL) {
        if (TcpSessionPacketIsStreamStarter(p) == 1) {
            if (TcpSessionReuseDoneEnough(p, f, tcp_ssn) == 1) {
                return 1;
            }
        }
    }
    return 0;
}

TmEcode StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueueNoLock *pq)
{
    DEBUG_VALIDATE_BUG_ON(p->flow == NULL);
    if (unlikely(p->flow == NULL)) {
        return TM_ECODE_OK;
    }

    StreamTcpThread *stt = (StreamTcpThread *)data;

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);
#ifdef DEBUG
    t_pcapcnt = p->pcap_cnt;
#endif

    if (!(PKT_IS_TCP(p))) {
        return TM_ECODE_OK;
    }

    HandleThreadId(tv, p, stt);

    /* only TCP packets with a flow from here */

    if (!(p->flags & PKT_PSEUDO_STREAM_END)) {
        if (stream_config.flags & STREAMTCP_INIT_FLAG_CHECKSUM_VALIDATION) {
            if (StreamTcpValidateChecksum(p) == 0) {
                StatsIncr(tv, stt->counter_tcp_invalid_checksum);
                return TM_ECODE_OK;
            }
        } else {
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    } else {
        p->flags |= PKT_IGNORE_CHECKSUM; //TODO check that this is set at creation
    }
    AppLayerProfilingReset(stt->ra_ctx->app_tctx);

    (void)StreamTcpPacket(tv, p, stt, pq);

    return TM_ECODE_OK;
}

TmEcode StreamTcpThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();
    StreamTcpThread *stt = SCMalloc(sizeof(StreamTcpThread));
    if (unlikely(stt == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(stt, 0, sizeof(StreamTcpThread));
    stt->ssn_pool_id = -1;

    *data = (void *)stt;

    stt->counter_tcp_sessions = StatsRegisterCounter("tcp.sessions", tv);
    stt->counter_tcp_ssn_memcap = StatsRegisterCounter("tcp.ssn_memcap_drop", tv);
    stt->counter_tcp_pseudo = StatsRegisterCounter("tcp.pseudo", tv);
    stt->counter_tcp_pseudo_failed = StatsRegisterCounter("tcp.pseudo_failed", tv);
    stt->counter_tcp_invalid_checksum = StatsRegisterCounter("tcp.invalid_checksum", tv);
    stt->counter_tcp_midstream_pickups = StatsRegisterCounter("tcp.midstream_pickups", tv);
    stt->counter_tcp_wrong_thread = StatsRegisterCounter("tcp.pkt_on_wrong_thread", tv);

    /* init reassembly ctx */
    stt->ra_ctx = StreamTcpReassembleInitThreadCtx(tv);
    if (stt->ra_ctx == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    stt->ra_ctx->counter_tcp_segment_memcap = StatsRegisterCounter("tcp.segment_memcap_drop", tv);
    stt->ra_ctx->counter_tcp_stream_depth = StatsRegisterCounter("tcp.stream_depth_reached", tv);
    stt->ra_ctx->counter_tcp_reass_gap = StatsRegisterCounter("tcp.reassembly_gap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap = StatsRegisterCounter("tcp.overlap", tv);
    stt->ra_ctx->counter_tcp_reass_overlap_diff_data = StatsRegisterCounter("tcp.overlap_diff_data", tv);

    stt->ra_ctx->counter_tcp_reass_data_normal_fail = StatsRegisterCounter("tcp.insert_data_normal_fail", tv);
    stt->ra_ctx->counter_tcp_reass_data_overlap_fail = StatsRegisterCounter("tcp.insert_data_overlap_fail", tv);
    stt->ra_ctx->counter_tcp_reass_list_fail = StatsRegisterCounter("tcp.insert_list_fail", tv);


    SCLogDebug("StreamTcp thread specific ctx online at %p, reassembly ctx %p",
                stt, stt->ra_ctx);

    SCMutexLock(&ssn_pool_mutex);
    if (ssn_pool == NULL) {
        ssn_pool = PoolThreadInit(1, /* thread */
                0, /* unlimited */
                stream_config.prealloc_sessions,
                sizeof(TcpSession),
                StreamTcpSessionPoolAlloc,
                StreamTcpSessionPoolInit, NULL,
                StreamTcpSessionPoolCleanup, NULL);
        stt->ssn_pool_id = 0;
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    } else {
        /* grow ssn_pool until we have a element for our thread id */
        stt->ssn_pool_id = PoolThreadExpand(ssn_pool);
        SCLogDebug("pool size %d, thread ssn_pool_id %d", PoolThreadSize(ssn_pool), stt->ssn_pool_id);
    }
    SCMutexUnlock(&ssn_pool_mutex);
    if (stt->ssn_pool_id < 0 || ssn_pool == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "failed to setup/expand stream session pool. Expand stream.memcap?");
        SCReturnInt(TM_ECODE_FAILED);
    }

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

/**
 *  \brief   Function to check the validity of the RST packets based on the
 *           target OS of the given packet.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 *
 *  \retval 0 unacceptable RST
 *  \retval 1 acceptable RST
 *
 *  WebSense sends RST packets that are:
 *  - RST flag, win 0, ack 0, seq = nextseq
 *
 */

static int StreamTcpValidateRst(TcpSession *ssn, Packet *p)
{
    uint8_t os_policy;

    if (ssn->flags & STREAMTCP_FLAG_TIMESTAMP) {
        if (!StreamTcpValidateTimestamp(ssn, p)) {
            SCReturnInt(0);
        }
    }

    /* RST with data, it's complicated:

         4.2.2.12  RST Segment: RFC-793 Section 3.4

            A TCP SHOULD allow a received RST segment to include data.

            DISCUSSION
                 It has been suggested that a RST segment could contain
                 ASCII text that encoded and explained the cause of the
                 RST.  No standard has yet been established for such
                 data.
    */
    if (p->payload_len)
        StreamTcpSetEvent(p, STREAM_RST_WITH_DATA);

    /* Set up the os_policy to be used in validating the RST packets based on
       target system */
    if (PKT_IS_TOSERVER(p)) {
        if (ssn->server.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->server, p);

        os_policy = ssn->server.os_policy;

        if (p->tcph->th_flags & TH_ACK &&
                TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->server, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }

    } else {
        if (ssn->client.os_policy == 0)
            StreamTcpSetOSPolicy(&ssn->client, p);

        os_policy = ssn->client.os_policy;

        if (p->tcph->th_flags & TH_ACK &&
                TCP_GET_ACK(p) && StreamTcpValidateAck(ssn, &ssn->client, p) == -1) {
            SCLogDebug("ssn %p: rejecting because of invalid ack value", ssn);
            StreamTcpSetEvent(p, STREAM_RST_INVALID_ACK);
            SCReturnInt(0);
        }
    }

    /* RFC 2385 md5 signature header or RFC 5925 TCP AO headerpresent. Since we can't
     * validate these (requires key that is set/transfered out of band), we can't know
     * if the RST will be accepted or rejected by the end host. We accept it, but keep
     * tracking if the sender of it ignores it, which would be a sign of injection. */
    if (p->tcpvars.md5_option_present || p->tcpvars.ao_option_present) {
        TcpStream *receiver_stream;
        if (PKT_IS_TOSERVER(p)) {
            receiver_stream = &ssn->server;
        } else {
            receiver_stream = &ssn->client;
        }
        SCLogDebug("ssn %p: setting STREAMTCP_STREAM_FLAG_RST_RECV on receiver stream", ssn);
        receiver_stream->flags |= STREAMTCP_STREAM_FLAG_RST_RECV;
    }

    if (ssn->flags & STREAMTCP_FLAG_ASYNC) {
        if (PKT_IS_TOSERVER(p)) {
            if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                SCLogDebug("ssn %p: ASYNC accept RST", ssn);
                return 1;
            }
        } else {
            if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                SCLogDebug("ssn %p: ASYNC accept RST", ssn);
                return 1;
            }
        }
        SCLogDebug("ssn %p: ASYNC reject RST", ssn);
        return 0;
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
                if (SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    SCLogDebug("reset is valid! Packet SEQ: %" PRIu32 " Stream %u",
                                TCP_GET_SEQ(p), ssn->server.next_seq);
                    return 1;
                } else {
                    SCLogDebug("reset is not valid! Packet SEQ: %" PRIu32 " and"
                               " client SEQ: %" PRIu32 "",
                               TCP_GET_SEQ(p), ssn->server.next_seq);
                    return 0;
                }
            }
            break;
    }
    return 0;
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream.
 *
 *  It's passive except for:
 *  1. it sets the os policy on the stream if necessary
 *  2. it sets an event in the packet if necessary
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpValidateTimestamp (TcpSession *ssn, Packet *p)
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
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);
        uint32_t last_pkt_ts = sender_stream->last_pkt_ts;
        uint32_t last_ts = sender_stream->last_ts;

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
            switch (receiver_stream->os_policy) {
                case OS_POLICY_LINUX:
                case OS_POLICY_WINDOWS2K3:
                    /* Linux and windows 2003 does not allow the use of 0 as
                     * timestamp in the 3whs. */
                    check_ts = 0;
                    break;

                case OS_POLICY_OLD_LINUX:
                case OS_POLICY_WINDOWS:
                case OS_POLICY_VISTA:
                    if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) {
                        last_ts = ts;
                        check_ts = 0; /*next packet will be checked for validity
                                        and stream TS has been updated with this
                                        one.*/
                    }
                    break;
            }
        }

        if (receiver_stream->os_policy == OS_POLICY_HPUX11) {
            /* HPUX11 igoners the timestamp of out of order packets */
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
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX || stream_config.liberal_timestamps) {
                /* Linux accepts TS which are off by one.*/
                result = (int32_t) ((ts - last_ts) + 1);
            } else {
                result = (int32_t) (ts - last_ts);
            }

            SCLogDebug("result %"PRIi32", p->ts.tv_sec %"PRIuMAX"", result, (uintmax_t)p->ts.tv_sec);

            if (last_pkt_ts == 0 &&
                    (ssn->flags & STREAMTCP_FLAG_MIDSTREAM))
            {
                last_pkt_ts = p->ts.tv_sec;
            }

            if (result < 0) {
                SCLogDebug("timestamp is not valid last_ts "
                           "%" PRIu32 " p->tcpvars->ts %" PRIu32 " result "
                           "%" PRId32 "", last_ts, ts, result);
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                        (((uint32_t) p->ts.tv_sec) >
                            last_pkt_ts + PAWS_24DAYS))
            {
                SCLogDebug("packet is not valid last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                            last_pkt_ts, (uint32_t) p->ts.tv_sec);
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                        (((uint32_t) p->ts.tv_sec > (last_pkt_ts + PAWS_24DAYS))))
                {
                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}

/**
 *  \brief Function to check the validity of the received timestamp based on
 *         the target OS of the given stream and update the session.
 *
 *  \param ssn TCP session to which the given packet belongs
 *  \param p Packet which has to be checked for its validity
 *
 *  \retval 1 if the timestamp is valid
 *  \retval 0 if the timestamp is invalid
 */
static int StreamTcpHandleTimestamp (TcpSession *ssn, Packet *p)
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
    if (receiver_stream->os_policy == 0) {
        StreamTcpSetOSPolicy(receiver_stream, p);
    }

    if (TCP_HAS_TS(p)) {
        uint32_t ts = TCP_GET_TSVAL(p);

        if (sender_stream->flags & STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP) {
            /* The 3whs used the timestamp with 0 value. */
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
                    sender_stream->flags &= ~STREAMTCP_STREAM_FLAG_ZERO_TIMESTAMP;
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
                    /* Old Linux and windows allowed packet with 0 timestamp. */
                    break;
                default:
                    /* other OS simply drop the pakcet with 0 timestamp, when
                     * 3whs has valid timestamp*/
                    goto invalid;
            }
        }

        if (check_ts) {
            int32_t result = 0;

            SCLogDebug("ts %"PRIu32", last_ts %"PRIu32"", ts, sender_stream->last_ts);

            if (receiver_stream->os_policy == OS_POLICY_LINUX || stream_config.liberal_timestamps) {
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
                /* candidate for rejection */
                ret = 0;
            } else if ((sender_stream->last_ts != 0) &&
                        (((uint32_t) p->ts.tv_sec) >
                            sender_stream->last_pkt_ts + PAWS_24DAYS))
            {
                SCLogDebug("packet is not valid sender_stream->last_pkt_ts "
                           "%" PRIu32 " p->ts.tv_sec %" PRIu32 "",
                            sender_stream->last_pkt_ts, (uint32_t) p->ts.tv_sec);
                /* candidate for rejection */
                ret = 0;
            }

            if (ret == 1) {
                /* Update the timestamp and last seen packet time for this
                 * stream */
                if (SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p)))
                    sender_stream->last_ts = ts;

                sender_stream->last_pkt_ts = p->ts.tv_sec;

            } else if (ret == 0) {
                /* if the timestamp of packet is not valid then, check if the
                 * current stream timestamp is not so old. if so then we need to
                 * accept the packet and update the stream->last_ts (RFC 1323)*/
                if ((SEQ_EQ(sender_stream->next_seq, TCP_GET_SEQ(p))) &&
                        (((uint32_t) p->ts.tv_sec > (sender_stream->last_pkt_ts + PAWS_24DAYS))))
                {
                    sender_stream->last_ts = ts;
                    sender_stream->last_pkt_ts = p->ts.tv_sec;

                    SCLogDebug("timestamp considered valid anyway");
                } else {
                    goto invalid;
                }
            }
        }
    } else {
        /* Solaris stops using timestamps if a packet is received
           without a timestamp and timestamps were used on that stream. */
        if (receiver_stream->os_policy == OS_POLICY_SOLARIS)
            ssn->flags &= ~STREAMTCP_FLAG_TIMESTAMP;
    }

    SCReturnInt(1);

invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_TIMESTAMP);
    SCReturnInt(0);
}

/**
 *  \brief  Function to test the received ACK values against the stream window
 *          and previous ack value. ACK values should be higher than previous
 *          ACK value and less than the next_win value.
 *
 *  \param  ssn     TcpSession for state access
 *  \param  stream  TcpStream of which last_ack needs to be tested
 *  \param  p       Packet which is used to test the last_ack
 *
 *  \retval 0  ACK is valid, last_ack is updated if ACK was higher
 *  \retval -1 ACK is invalid
 */
static inline int StreamTcpValidateAck(TcpSession *ssn, TcpStream *stream, Packet *p)
{
    SCEnter();

    uint32_t ack = TCP_GET_ACK(p);

    /* fast track */
    if (SEQ_GT(ack, stream->last_ack) && SEQ_LEQ(ack, stream->next_win))
    {
        SCLogDebug("ACK in bounds");
        SCReturnInt(0);
    }
    /* fast track */
    else if (SEQ_EQ(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" == stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);
        SCReturnInt(0);
    }

    /* exception handling */
    if (SEQ_LT(ack, stream->last_ack)) {
        SCLogDebug("pkt ACK %"PRIu32" < stream last ACK %"PRIu32, TCP_GET_ACK(p), stream->last_ack);

        /* This is an attempt to get a 'left edge' value that we can check against.
         * It doesn't work when the window is 0, need to think of a better way. */

        if (stream->window != 0 && SEQ_LT(ack, (stream->last_ack - stream->window))) {
            SCLogDebug("ACK %"PRIu32" is before last_ack %"PRIu32" - window "
                    "%"PRIu32" = %"PRIu32, ack, stream->last_ack,
                    stream->window, stream->last_ack - stream->window);
            goto invalid;
        }

        SCReturnInt(0);
    }

    /* no further checks possible for ASYNC */
    if ((ssn->flags & STREAMTCP_FLAG_ASYNC) != 0) {
        SCReturnInt(0);
    }

    if (ssn->state > TCP_SYN_SENT && SEQ_GT(ack, stream->next_win)) {
        SCLogDebug("ACK %"PRIu32" is after next_win %"PRIu32, ack, stream->next_win);
        goto invalid;
    /* a toclient RST as a reponse to SYN, next_win is 0, ack will be isn+1, just like
     * the syn ack */
    } else if (ssn->state == TCP_SYN_SENT && PKT_IS_TOCLIENT(p) &&
            p->tcph->th_flags & TH_RST &&
            SEQ_EQ(ack, stream->isn + 1)) {
        SCReturnInt(0);
    }

    SCLogDebug("default path leading to invalid: ACK %"PRIu32", last_ack %"PRIu32
        " next_win %"PRIu32, ack, stream->last_ack, stream->next_win);
invalid:
    StreamTcpSetEvent(p, STREAM_PKT_INVALID_ACK);
    SCReturnInt(-1);
}

/** \brief update reassembly progress

 * \param ssn TCP Session
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpUpdateAppLayerProgress(TcpSession *ssn, char direction,
        const uint32_t progress)
{
    if (direction) {
        ssn->server.app_progress_rel += progress;
    } else {
        ssn->client.app_progress_rel += progress;
    }
}

/** \brief disable reassembly

 *  Disable app layer and set raw inspect to no longer accept new data.
 *  Stream engine will then fully disable raw after last inspection.
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetSessionNoReassemblyFlag(TcpSession *ssn, char direction)
{
    ssn->flags |= STREAMTCP_FLAG_APP_LAYER_DISABLED;
    if (direction) {
        ssn->server.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED;
    } else {
        ssn->client.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED;
    }
}

/** \brief  Set the No reassembly flag for the given direction in given TCP
 *          session.
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetDisableRawReassemblyFlag(TcpSession *ssn, char direction)
{
    direction ? (ssn->server.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED) :
                (ssn->client.flags |= STREAMTCP_STREAM_FLAG_NEW_RAW_DISABLED);
}

/** \brief enable bypass
 *
 * \param ssn TCP Session to set the flag in
 * \param direction direction to set the flag in: 0 toserver, 1 toclient
 */
void StreamTcpSetSessionBypassFlag(TcpSession *ssn)
{
    ssn->flags |= STREAMTCP_FLAG_BYPASS;
}

#define PSEUDO_PKT_SET_IPV4HDR(nipv4h,ipv4h) do { \
        IPV4_SET_RAW_VER(nipv4h, IPV4_GET_RAW_VER(ipv4h)); \
        IPV4_SET_RAW_HLEN(nipv4h, IPV4_GET_RAW_HLEN(ipv4h)); \
        IPV4_SET_RAW_IPLEN(nipv4h, IPV4_GET_RAW_IPLEN(ipv4h)); \
        IPV4_SET_RAW_IPTOS(nipv4h, IPV4_GET_RAW_IPTOS(ipv4h)); \
        IPV4_SET_RAW_IPPROTO(nipv4h, IPV4_GET_RAW_IPPROTO(ipv4h)); \
        (nipv4h)->s_ip_src = IPV4_GET_RAW_IPDST(ipv4h); \
        (nipv4h)->s_ip_dst = IPV4_GET_RAW_IPSRC(ipv4h); \
    } while (0)

#define PSEUDO_PKT_SET_IPV6HDR(nipv6h,ipv6h) do { \
        (nipv6h)->s_ip6_src[0] = (ipv6h)->s_ip6_dst[0]; \
        (nipv6h)->s_ip6_src[1] = (ipv6h)->s_ip6_dst[1]; \
        (nipv6h)->s_ip6_src[2] = (ipv6h)->s_ip6_dst[2]; \
        (nipv6h)->s_ip6_src[3] = (ipv6h)->s_ip6_dst[3]; \
        (nipv6h)->s_ip6_dst[0] = (ipv6h)->s_ip6_src[0]; \
        (nipv6h)->s_ip6_dst[1] = (ipv6h)->s_ip6_src[1]; \
        (nipv6h)->s_ip6_dst[2] = (ipv6h)->s_ip6_src[2]; \
        (nipv6h)->s_ip6_dst[3] = (ipv6h)->s_ip6_src[3]; \
        IPV6_SET_RAW_NH(nipv6h, IPV6_GET_RAW_NH(ipv6h));    \
    } while (0)

#define PSEUDO_PKT_SET_TCPHDR(ntcph,tcph) do { \
        COPY_PORT((tcph)->th_dport, (ntcph)->th_sport); \
        COPY_PORT((tcph)->th_sport, (ntcph)->th_dport); \
        (ntcph)->th_seq = (tcph)->th_ack; \
        (ntcph)->th_ack = (tcph)->th_seq; \
    } while (0)

/**
 * \brief   Function to fetch a packet from the packet allocation queue for
 *          creation of the pseudo packet from the reassembled stream.
 *
 * @param parent    Pointer to the parent of the pseudo packet
 * @param pkt       pointer to the raw packet of the parent
 * @param len       length of the packet
 * @return          upon success returns the pointer to the new pseudo packet
 *                  otherwise NULL
 */
Packet *StreamTcpPseudoSetup(Packet *parent, uint8_t *pkt, uint32_t len)
{
    SCEnter();

    if (len == 0) {
        SCReturnPtr(NULL, "Packet");
    }

    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    p->proto = parent->proto;
    p->datalink = parent->datalink;

    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;

    FlowReference(&p->flow, parent->flow);
    /* set tunnel flags */

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(p);

    return p;
}

/** \brief Create a pseudo packet injected into the engine to signal the
 *         opposing direction of this stream trigger detection/logging.
 *
 *  \param parent real packet
 *  \param pq packet queue to store the new pseudo packet in
 *  \param dir 0 ts 1 tc
 */
static void StreamTcpPseudoPacketCreateDetectLogFlush(ThreadVars *tv,
        StreamTcpThread *stt, Packet *parent,
        TcpSession *ssn, PacketQueueNoLock *pq, int dir)
{
    SCEnter();
    Flow *f = parent->flow;

    if (parent->flags & PKT_PSEUDO_DETECTLOG_FLUSH) {
        SCReturn;
    }

    Packet *np = PacketPoolGetPacket();
    if (np == NULL) {
        SCReturn;
    }
    PKT_SET_SRC(np, PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH);

    np->tenant_id = f->tenant_id;
    np->datalink = DLT_RAW;
    np->proto = IPPROTO_TCP;
    FlowReference(&np->flow, f);
    np->flags |= PKT_STREAM_EST;
    np->flags |= PKT_HAS_FLOW;
    np->flags |= PKT_IGNORE_CHECKSUM;
    np->flags |= PKT_PSEUDO_DETECTLOG_FLUSH;
    np->vlan_id[0] = f->vlan_id[0];
    np->vlan_id[1] = f->vlan_id[1];
    np->vlan_idx = f->vlan_idx;
    np->livedev = (struct LiveDevice_ *)f->livedev;

    if (f->flags & FLOW_NOPACKET_INSPECTION) {
        DecodeSetNoPacketInspectionFlag(np);
    }
    if (f->flags & FLOW_NOPAYLOAD_INSPECTION) {
        DecodeSetNoPayloadInspectionFlag(np);
    }

    if (dir == 0) {
        SCLogDebug("pseudo is to_server");
        np->flowflags |= FLOW_PKT_TOSERVER;
    } else {
        SCLogDebug("pseudo is to_client");
        np->flowflags |= FLOW_PKT_TOCLIENT;
    }
    np->flowflags |= FLOW_PKT_ESTABLISHED;
    np->payload = NULL;
    np->payload_len = 0;

    if (FLOW_IS_IPV4(f)) {
        if (dir == 0) {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->src);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->dst);
            np->sp = f->sp;
            np->dp = f->dp;
        } else {
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, &np->dst);
            FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, &np->src);
            np->sp = f->dp;
            np->dp = f->sp;
        }

        /* Check if we have enough room in direct data. We need ipv4 hdr + tcp hdr.
         * Force an allocation if it is not the case.
         */
        if (GET_PKT_DIRECT_MAX_SIZE(np) <  40) {
            if (PacketCallocExtPkt(np, 40) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        np->ip4h = (IPV4Hdr *)GET_PKT_DATA(np);
        /* version 4 and length 20 bytes for the tcp header */
        np->ip4h->ip_verhl = 0x45;
        np->ip4h->ip_tos = 0;
        np->ip4h->ip_len = htons(40);
        np->ip4h->ip_id = 0;
        np->ip4h->ip_off = 0;
        np->ip4h->ip_ttl = 64;
        np->ip4h->ip_proto = IPPROTO_TCP;
        if (dir == 0) {
            np->ip4h->s_ip_src.s_addr = f->src.addr_data32[0];
            np->ip4h->s_ip_dst.s_addr = f->dst.addr_data32[0];
        } else {
            np->ip4h->s_ip_src.s_addr = f->dst.addr_data32[0];
            np->ip4h->s_ip_dst.s_addr = f->src.addr_data32[0];
        }

        /* set the tcp header */
        np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 20);

        SET_PKT_LEN(np, 40); /* ipv4 hdr + tcp hdr */

    } else if (FLOW_IS_IPV6(f)) {
        if (dir == 0) {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->src);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->dst);
            np->sp = f->sp;
            np->dp = f->dp;
        } else {
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, &np->dst);
            FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, &np->src);
            np->sp = f->dp;
            np->dp = f->sp;
        }

        /* Check if we have enough room in direct data. We need ipv6 hdr + tcp hdr.
         * Force an allocation if it is not the case.
         */
        if (GET_PKT_DIRECT_MAX_SIZE(np) <  60) {
            if (PacketCallocExtPkt(np, 60) == -1) {
                goto error;
            }
        }
        /* set the ip header */
        np->ip6h = (IPV6Hdr *)GET_PKT_DATA(np);
        /* version 6 */
        np->ip6h->s_ip6_vfc = 0x60;
        np->ip6h->s_ip6_flow = 0;
        np->ip6h->s_ip6_nxt = IPPROTO_TCP;
        np->ip6h->s_ip6_plen = htons(20);
        np->ip6h->s_ip6_hlim = 64;
        if (dir == 0) {
            np->ip6h->s_ip6_src[0] = f->src.addr_data32[0];
            np->ip6h->s_ip6_src[1] = f->src.addr_data32[1];
            np->ip6h->s_ip6_src[2] = f->src.addr_data32[2];
            np->ip6h->s_ip6_src[3] = f->src.addr_data32[3];
            np->ip6h->s_ip6_dst[0] = f->dst.addr_data32[0];
            np->ip6h->s_ip6_dst[1] = f->dst.addr_data32[1];
            np->ip6h->s_ip6_dst[2] = f->dst.addr_data32[2];
            np->ip6h->s_ip6_dst[3] = f->dst.addr_data32[3];
        } else {
            np->ip6h->s_ip6_src[0] = f->dst.addr_data32[0];
            np->ip6h->s_ip6_src[1] = f->dst.addr_data32[1];
            np->ip6h->s_ip6_src[2] = f->dst.addr_data32[2];
            np->ip6h->s_ip6_src[3] = f->dst.addr_data32[3];
            np->ip6h->s_ip6_dst[0] = f->src.addr_data32[0];
            np->ip6h->s_ip6_dst[1] = f->src.addr_data32[1];
            np->ip6h->s_ip6_dst[2] = f->src.addr_data32[2];
            np->ip6h->s_ip6_dst[3] = f->src.addr_data32[3];
        }

        /* set the tcp header */
        np->tcph = (TCPHdr *)((uint8_t *)GET_PKT_DATA(np) + 40);

        SET_PKT_LEN(np, 60); /* ipv6 hdr + tcp hdr */
    }

    np->tcph->th_offx2 = 0x50;
    np->tcph->th_flags |= TH_ACK;
    np->tcph->th_win = 10;
    np->tcph->th_urp = 0;

    /* to server */
    if (dir == 0) {
        np->tcph->th_sport = htons(f->sp);
        np->tcph->th_dport = htons(f->dp);

        np->tcph->th_seq = htonl(ssn->client.next_seq);
        np->tcph->th_ack = htonl(ssn->server.last_ack);

    /* to client */
    } else {
        np->tcph->th_sport = htons(f->dp);
        np->tcph->th_dport = htons(f->sp);

        np->tcph->th_seq = htonl(ssn->server.next_seq);
        np->tcph->th_ack = htonl(ssn->client.last_ack);
    }

    /* use parent time stamp */
    memcpy(&np->ts, &parent->ts, sizeof(struct timeval));

    SCLogDebug("np %p", np);
    PacketEnqueueNoLock(pq, np);

    StatsIncr(tv, stt->counter_tcp_pseudo);
    SCReturn;
error:
    FlowDeReference(&np->flow);
    SCReturn;
}

/** \brief create packets in both directions to flush out logging
 *         and detection before switching protocols.
 *         In IDS mode, create first in packet dir, 2nd in opposing
 *         In IPS mode, do the reverse.
 *         Flag TCP engine that data needs to be inspected regardless
 *         of how far we are wrt inspect limits.
 */
void StreamTcpDetectLogFlush(ThreadVars *tv, StreamTcpThread *stt, Flow *f, Packet *p,
        PacketQueueNoLock *pq)
{
    TcpSession *ssn = f->protoctx;
    ssn->client.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    ssn->server.flags |= STREAMTCP_STREAM_FLAG_TRIGGER_RAW;
    bool ts = PKT_IS_TOSERVER(p) ? true : false;
    ts ^= StreamTcpInlineMode();
    StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^0);
    StreamTcpPseudoPacketCreateDetectLogFlush(tv, stt, p, ssn, pq, ts^1);
}

/**
 * \brief Run callback function on each TCP segment
 *
 * \note when stream engine is running in inline mode all segments are used,
 *       in IDS/non-inline mode only ack'd segments are iterated.
 *
 * \note Must be called under flow lock.
 *
 * \return -1 in case of error, the number of segment in case of success
 *
 */
int StreamTcpSegmentForEach(const Packet *p, uint8_t flag, StreamSegmentCallback CallbackFunc, void *data)
{
    TcpSession *ssn = NULL;
    TcpStream *stream = NULL;
    int ret = 0;
    int cnt = 0;

    if (p->flow == NULL)
        return 0;

    ssn = (TcpSession *)p->flow->protoctx;

    if (ssn == NULL) {
        return 0;
    }

    if (flag & FLOW_PKT_TOSERVER) {
        stream = &(ssn->server);
    } else {
        stream = &(ssn->client);
    }

    /* for IDS, return ack'd segments. For IPS all. */
    TcpSegment *seg;
    RB_FOREACH(seg, TCPSEG, &stream->seg_tree) {
        if (!(stream_config.flags & STREAMTCP_INIT_FLAG_INLINE)) {
            if (PKT_IS_PSEUDOPKT(p)) {
                /* use un-ACK'd data as well */
            } else {
                /* in IDS mode, use ACK'd data */
                if (SEQ_GEQ(seg->seq, stream->last_ack)) {
                    break;
                }
            }
        }

        const uint8_t *seg_data;
        uint32_t seg_datalen;
        StreamingBufferSegmentGetData(&stream->sb, &seg->sbseg, &seg_data, &seg_datalen);

        ret = CallbackFunc(p, data, seg_data, seg_datalen);
        if (ret != 1) {
            SCLogDebug("Callback function has failed");
            return -1;
        }

        cnt++;
    }
    return cnt;
}

int StreamTcpBypassEnabled(void)
{
    return (stream_config.flags & STREAMTCP_INIT_FLAG_BYPASS);
}

/**
 *  \brief See if stream engine is operating in inline mode
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int StreamTcpInlineMode(void)
{
    return (stream_config.flags & STREAMTCP_INIT_FLAG_INLINE) ? 1 : 0;
}


void TcpSessionSetReassemblyDepth(TcpSession *ssn, uint32_t size)
{
    if (size > ssn->reassembly_depth || size == 0) {
        ssn->reassembly_depth = size;
    }

    return;
}

const char *StreamTcpStateAsString(const enum TcpState state)
{
    const char *tcp_state = NULL;
    switch (state) {
        case TCP_NONE:
            tcp_state = "none";
            break;
        case TCP_LISTEN:
            tcp_state = "listen";
            break;
        case TCP_SYN_SENT:
            tcp_state = "syn_sent";
            break;
        case TCP_SYN_RECV:
            tcp_state = "syn_recv";
            break;
        case TCP_ESTABLISHED:
            tcp_state = "established";
            break;
        case TCP_FIN_WAIT1:
            tcp_state = "fin_wait1";
            break;
        case TCP_FIN_WAIT2:
            tcp_state = "fin_wait2";
            break;
        case TCP_TIME_WAIT:
            tcp_state = "time_wait";
            break;
        case TCP_LAST_ACK:
            tcp_state = "last_ack";
            break;
        case TCP_CLOSE_WAIT:
            tcp_state = "close_wait";
            break;
        case TCP_CLOSING:
            tcp_state = "closing";
            break;
        case TCP_CLOSED:
            tcp_state = "closed";
            break;
    }
    return tcp_state;
}

const char *StreamTcpSsnStateAsString(const TcpSession *ssn)
{
    if (ssn == NULL)
        return NULL;
    return StreamTcpStateAsString(ssn->state);
}

#ifdef UNITTESTS

#define SET_ISN(stream, setseq)             \
    (stream)->isn = (setseq);               \
    (stream)->base_seq = (setseq) + 1

/**
 *  \test   Test the allocation of TCP session for a given packet from the
 *          ssn_pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest01 (void)
{
    StreamTcpThread stt;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    memset (&f, 0, sizeof(Flow));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    TcpSession *ssn = StreamTcpNewSession(p, 0);
    if (ssn == NULL) {
        printf("Session can not be allocated: ");
        goto end;
    }
    f.protoctx = ssn;

    if (f.alparser != NULL) {
        printf("AppLayer field not set to NULL: ");
        goto end;
    }
    if (ssn->state != 0) {
        printf("TCP state field not set to 0: ");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the deallocation of TCP session for a given packet and return
 *          the memory back to ssn_pool and corresponding segments to segment
 *          pool.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest02 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(pq));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->flowflags = FLOW_PKT_TOCLIENT;
    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    StreamTcpSessionClear(p->flow->protoctx);
    //StreamTcpUTClearSession(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN packet of the session. The session is setup only if midstream
 *          sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest03 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(pq));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_SYN|TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 20 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          SYN/ACK packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest04 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(pq));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;

    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(9);
    p->tcph->th_ack = htonl(19);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 10 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 20)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we missed the intial
 *          3WHS packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest05 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(13);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, 4); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(19);
    p->tcph->th_ack = htonl(16);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, 4); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 16 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we have seen only the
 *          FIN, RST packets packet of the session. The session is setup only if
 *          midstream sessions are allowed to setup.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest06 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    TcpSession ssn;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_flags = TH_FIN;
    p->tcph = &tcph;

    /* StreamTcpPacket returns -1 on unsolicited FIN */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed: ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't: ");
        goto end;
    }

    p->tcph->th_flags = TH_RST;
    /* StreamTcpPacket returns -1 on unsolicited RST */
    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("StreamTcpPacket failed (2): ");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx)) != NULL) {
        printf("we have a ssn while we shouldn't (2): ");
        goto end;
    }

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the working on PAWS. The packet will be dropped by stream, as
 *          its timestamp is old, although the segment is in the window.
 */

static int StreamTcpTest07 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};
    PacketQueueNoLock pq;

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = TRUE;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 2;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) != -1);

    FAIL_IF(((TcpSession *) (p->flow->protoctx))->client.next_seq != 11);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the working on PAWS. The packet will be accpeted by engine as
 *          the timestamp is valid and it is in window.
 */

static int StreamTcpTest08 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};

    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->tcpvars.ts_set = TRUE;
    p->tcpvars.ts_val = 10;
    p->tcpvars.ts_ecr = 11;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(20);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    p->tcpvars.ts_val = 12;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(((TcpSession *) (p->flow->protoctx))->client.next_seq != 12);

    StreamTcpSessionClear(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the working of No stream reassembly flag. The stream will not
 *          reassemble the segment if the flag is set.
 */

static int StreamTcpTest09 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[1] = {0x42};

    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.midstream = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;

    p->payload = payload;
    p->payload_len = 1;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(12);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(p->flow->protoctx == NULL);

    StreamTcpSetSessionNoReassemblyFlag(((TcpSession *)(p->flow->protoctx)), 0);

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    TcpSession *ssn = p->flow->protoctx;
    FAIL_IF_NULL(ssn);
    TcpSegment *seg = RB_MIN(TCPSEG, &ssn->client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCPSEG_RB_NEXT(seg) != NULL);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we see all the packets in that stream from start.
 */

static int StreamTcpTest10 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.async_oneside = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED);

    FAIL_IF(! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC));

    FAIL_IF(((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11);

    StreamTcpSessionClear(p->flow->protoctx);

    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN packet of that stream.
 */

static int StreamTcpTest11 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.async_oneside = TRUE;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(1);
    tcph.th_flags = TH_SYN|TH_ACK;
    p->tcph = &tcph;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    p->tcph->th_seq = htonl(2);
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    FAIL_IF(StreamTcpPacket(&tv, p, &stt, &pq) == -1);

    TcpSession *ssn = p->flow->protoctx;
    FAIL_IF((ssn->flags & STREAMTCP_FLAG_ASYNC) == 0);
    FAIL_IF(ssn->state != TCP_ESTABLISHED);

    FAIL_IF(ssn->server.last_ack != 11);
    FAIL_IF(ssn->client.next_seq != 14);

    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    PASS;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest12 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 6 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 11) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session when we are seeing asynchronous
 *          stream, while we missed the SYN and SYN/ACK packets in that stream.
 *          Later, we start to receive the packet from other end stream too.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest13 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(11);
    tcph.th_flags = TH_ACK;
    p->tcph = &tcph;
    int ret = 0;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(6);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.async_oneside != TRUE) {
        ret = 1;
        goto end;
    }

    if (! (((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_ASYNC)) {
        printf("failed in setting asynchronous session\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("failed in setting state\n");
        goto end;
    }

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(9);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.last_ack != 9 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 14) {
        printf("failed in seq %"PRIu32" match\n",
                ((TcpSession *)(p->flow->protoctx))->client.last_ack);
        goto end;
    }

    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
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
static const char *StreamTcpParseOSPolicy (char *conf_var_name)
{
    SCEnter();
    char conf_var_type_name[15] = "host-os-policy";
    char *conf_var_full_name = NULL;
    const char *conf_var_value = NULL;

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
        SCLogError(SC_ERR_INVALID_VALUE, "Error in making the conf full name");
        goto end;
    }

    if (ConfGet(conf_var_full_name, &conf_var_value) != 1) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Error in getting conf value for conf name %s",
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

static int StreamTcpTest14 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

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
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.0.2");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest01 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(10);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(21);
    p->tcph->th_ack = htonl(10);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK, but the SYN/ACK does
 *          not have the right SEQ
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest02 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(21); /* the SYN/ACK uses the SEQ from the first SYN pkt */
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1) {
        printf("SYN/ACK pkt not rejected but it should have: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   set up a TCP session using the 4WHS:
 *          SYN, SYN, SYN/ACK, ACK: however the SYN/ACK and ACK
 *          are part of a normal 3WHS
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcp4WHSTest03 (void)
{
    int ret = 0;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    p->flow = &f;

    StreamTcpUTInit(&stt.ra_ctx);

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = 0;
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = 0;
    p->tcph->th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if ((!(((TcpSession *)(p->flow->protoctx))->flags & STREAMTCP_FLAG_4WHS))) {
        printf("STREAMTCP_FLAG_4WHS flag not set: ");
        goto end;
    }

    p->tcph->th_seq = htonl(30);
    p->tcph->th_ack = htonl(11);
    p->tcph->th_flags = TH_SYN|TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(11);
    p->tcph->th_ack = htonl(31);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("state is not ESTABLISHED: ");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest15 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

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
    addr.s_addr = inet_addr("192.168.0.20");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.20");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_WINDOWS && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_LINUX)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_WINDOWS,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_LINUX);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1"
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest16 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

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
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("192.168.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_WINDOWS)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_WINDOWS);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the setting up a OS policy. Te OS policy values are defined in
 *          the config string "dummy_conf_string1". To check the setting of
 *          Default os policy
 *
 *  \retval On success it returns 1 and on failure 0
 */

static int StreamTcpTest17 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    uint8_t payload[4];
    struct in_addr addr;
    IPV4Hdr ipv4h;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&addr, 0, sizeof(addr));
    memset(&ipv4h, 0, sizeof(ipv4h));
    FLOW_INITIALIZE(&f);
    p->flow = &f;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

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
    addr.s_addr = inet_addr("192.168.0.1");
    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(10);
    tcph.th_ack = htonl(20);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p->tcph = &tcph;
    p->dst.family = AF_INET;
    p->dst.address.address_un_data32[0] = addr.s_addr;
    p->ip4h = &ipv4h;

    StreamTcpCreateTestPacket(payload, 0x41, 3, sizeof(payload)); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    FLOWLOCK_WRLOCK(&f);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(20);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x42, 3, sizeof(payload)); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(15);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(14);
    p->tcph->th_ack = htonl(23);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x43, 3, sizeof(payload)); /*CCC*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    addr.s_addr = inet_addr("10.1.1.1");
    p->tcph->th_seq = htonl(25);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->dst.address.address_un_data32[0] = addr.s_addr;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_seq = htonl(24);
    p->tcph->th_ack = htonl(13);
    p->tcph->th_flags = TH_ACK|TH_PUSH;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x44, 3, sizeof(payload)); /*DDD*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    if (stream_config.midstream != TRUE) {
        ret = 1;
        goto end;
    }
    if (((TcpSession *)(p->flow->protoctx))->state != TCP_ESTABLISHED)
        goto end;

    if (((TcpSession *)(p->flow->protoctx))->client.next_seq != 13 &&
            ((TcpSession *)(p->flow->protoctx))->server.next_seq != 23) {
        printf("failed in next_seq match client.next_seq %"PRIu32""
                " server.next_seq %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->client.next_seq,
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->client.os_policy !=
            OS_POLICY_LINUX && ((TcpSession *)
            (p->flow->protoctx))->server.os_policy != OS_POLICY_DEFAULT)
    {
        printf("failed in setting up OS policy, client.os_policy: %"PRIu8""
                " should be %"PRIu8" and server.os_policy: %"PRIu8""
                " should be %"PRIu8"\n", ((TcpSession *)
                (p->flow->protoctx))->client.os_policy, (uint8_t)OS_POLICY_LINUX,
                ((TcpSession *)(p->flow->protoctx))->server.os_policy,
                (uint8_t)OS_POLICY_DEFAULT);
        goto end;
    }
    StreamTcpSessionPktFree(p);

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    FLOWLOCK_UNLOCK(&f);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest18 (void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS)
        goto end;

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest19 (void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_WINDOWS) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8": ",
                (uint8_t)OS_POLICY_WINDOWS, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest20 (void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "linux";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.0.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest21 (void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "linux";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("192.168.1.30");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_LINUX) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_LINUX, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}
/** \test   Test the various OS policies based on different IP addresses from
            confuguration defined in 'dummy_conf_string1' */
static int StreamTcpTest22 (void)
{
    StreamTcpThread stt;
    struct in_addr addr;
    char os_policy_name[10] = "windows";
    const char *ip_addr;
    TcpStream stream;
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    IPV4Hdr ipv4h;
    int ret = 0;

    memset(&addr, 0, sizeof(addr));
    memset(&stream, 0, sizeof(stream));
    memset(&ipv4h, 0, sizeof(ipv4h));

    StreamTcpUTInit(&stt.ra_ctx);
    SCHInfoCleanResources();

    /* Load the config string in to parser */
    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string1, strlen(dummy_conf_string1));

    /* Get the IP address as string and add it to Host info tree for lookups */
    ip_addr = StreamTcpParseOSPolicy(os_policy_name);
    SCHInfoAddHostOSInfo(os_policy_name, ip_addr, -1);

    p->dst.family = AF_INET;
    p->ip4h = &ipv4h;
    addr.s_addr = inet_addr("123.231.2.1");
    p->dst.address.address_un_data32[0] = addr.s_addr;
    StreamTcpSetOSPolicy(&stream, p);

    if (stream.os_policy != OS_POLICY_DEFAULT) {
        printf("expected os_policy: %"PRIu8" but received %"PRIu8"\n",
                (uint8_t)OS_POLICY_DEFAULT, stream.os_policy);
        goto end;
    }

    ret = 1;
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest23(void)
{
    StreamTcpThread stt;
    TcpSession ssn;
    Flow f;
    TCPHdr tcph;
    uint8_t packet[1460] = "";
    ThreadVars tv;
    PacketQueueNoLock pq;

    Packet *p = PacketGetFromAlloc();
    FAIL_IF(p == NULL);

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&tv, 0, sizeof (ThreadVars));

    StreamTcpUTInit(&stt.ra_ctx);
    StreamTcpUTSetupSession(&ssn);
    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    SET_ISN(&ssn.client, 3184324452UL);

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419609UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324453UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 6;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    TcpSegment *seg = RB_MAX(TCPSEG, &ssn.client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCP_SEG_LEN(seg) != 2);

    StreamTcpUTClearSession(&ssn);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) > 0);
    PASS;
}

/** \test   Test the stream mem leaks conditions. */
static int StreamTcpTest24(void)
{
    StreamTcpThread stt;
    TcpSession ssn;
    Packet *p = PacketGetFromAlloc();
    FAIL_IF (p == NULL);
    Flow f;
    TCPHdr tcph;
    uint8_t packet[1460] = "";
    ThreadVars tv;
    memset(&tv, 0, sizeof (ThreadVars));
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    StreamTcpUTInit(&stt.ra_ctx);
    StreamTcpUTSetupSession(&ssn);

    memset(&f, 0, sizeof (Flow));
    memset(&tcph, 0, sizeof (TCPHdr));
    FLOW_INITIALIZE(&f);
    ssn.client.os_policy = OS_POLICY_BSD;
    f.protoctx = &ssn;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->flow = &f;
    tcph.th_win = 5480;
    tcph.th_flags = TH_PUSH | TH_ACK;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload = packet;
    //ssn.client.ra_app_base_seq = ssn.client.ra_raw_base_seq = ssn.client.last_ack = 3184324453UL;
    SET_ISN(&ssn.client, 3184324453UL);

    p->tcph->th_seq = htonl(3184324455UL);
    p->tcph->th_ack = htonl(3373419621UL);
    p->payload_len = 4;

    FAIL_IF (StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419633UL);
    p->payload_len = 2;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    p->tcph->th_seq = htonl(3184324459UL);
    p->tcph->th_ack = htonl(3373419657UL);
    p->payload_len = 4;

    FAIL_IF(StreamTcpReassembleHandleSegment(&tv, stt.ra_ctx, &ssn, &ssn.client, p, &pq) == -1);

    TcpSegment *seg = RB_MAX(TCPSEG, &ssn.client.seg_tree);
    FAIL_IF_NULL(seg);
    FAIL_IF(TCP_SEG_LEN(seg) != 4);

    StreamTcpUTClearSession(&ssn);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) > 0);
    PASS;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest25(void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest26(void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the initialization of tcp streams with congestion flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest27(void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(6);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x42, 3, 4); /*BBB*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL)
        goto end;

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test   Test the memcap incrementing/decrementing and memcap check */
static int StreamTcpTest28(void)
{
    StreamTcpThread stt;
    StreamTcpUTInit(&stt.ra_ctx);

    uint32_t memuse = SC_ATOMIC_GET(st_memuse);

    StreamTcpIncrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) != (memuse+500));

    StreamTcpDecrMemuse(500);
    FAIL_IF(SC_ATOMIC_GET(st_memuse) != memuse);

    FAIL_IF(StreamTcpCheckMemcap(500) != 1);

    FAIL_IF(StreamTcpCheckMemcap((memuse + SC_ATOMIC_GET(stream_config.memcap))) != 0);

    StreamTcpUTDeinit(stt.ra_ctx);

    FAIL_IF(SC_ATOMIC_GET(st_memuse) != 0);
    PASS;
}

#if 0
/**
 *  \test   Test the resetting of the sesison with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest29(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t packet[1460] = "";
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = packet;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    tcpvars.hlen = 20;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 119197101;
    ssn.server.window = 5184;
    ssn.server.next_win = 5184;
    ssn.server.last_ack = 119197101;
    ssn.server.ra_base_seq = 119197101;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 4;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(119197102);
    p.tcph->th_ack = htonl(15);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(15);
    p.tcph->th_ack = htonl(119197102);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the ssn.state should be TCP_ESTABLISHED(%"PRIu8"), not %"PRIu8""
                "\n", TCP_ESTABLISHED, ssn.state);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the overlapping of the packet with bad checksum packet and later
 *          send the malicious contents on the session. Engine should drop the
 *          packet with the bad checksum.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest30(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    uint8_t payload[9] = "AAAAAAAAA";
    uint8_t payload1[9] = "GET /EVIL";
    uint8_t expected_content[9] = { 0x47, 0x45, 0x54, 0x20, 0x2f, 0x45, 0x56,
                                    0x49, 0x4c };
    int result = 1;

    FLOW_INITIALIZE(&f);
    StreamTcpInitConfig(TRUE);

    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_BSD;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.payload = payload;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    ssn.state = TCP_ESTABLISHED;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_PUSH | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079940);
    p.payload = payload1;
    p.payload_len = 9;
    p.ip4h->ip_src = addr1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(20);
    p.payload_len = 0;
    p.ip4h->ip_src = addr;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                                 (uint16_t *)p.tcph,
                                                 (p.payload_len +
                                                  p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (StreamTcpCheckStreamContents(expected_content, 9, &ssn.client) != 1) {
        printf("the contents are not as expected(GET /EVIL), contents are: ");
        PrintRawDataFp(stdout, ssn.client.seg_list->payload, 9);
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the multiple SYN packet handling with bad checksum and timestamp
 *          value. Engine should drop the bad checksum packet and establish
 *          TCP session correctly.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest31(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpSession ssn;
    IPV4Hdr ipv4h;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    struct in_addr addr;
    struct in_addr addr1;
    TCPCache tcpc;
    TCPVars tcpvars;
    TcpStream server;
    TcpStream client;
    TCPOpt tcpopt;

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset (&ipv4h, 0, sizeof(IPV4Hdr));
    memset (&addr, 0, sizeof(addr));
    memset (&addr1, 0, sizeof(addr1));
    memset (&tcpc, 0, sizeof(tcpc));
    memset (&tcpvars, 0, sizeof(tcpvars));
    memset(&ssn, 0, sizeof (TcpSession));
    memset(&server, 0, sizeof (TcpStream));
    memset(&client, 0, sizeof (TcpStream));
    memset(&tcpopt, 0, sizeof (TCPOpt));
    int result = 1;

    StreamTcpInitConfig(TRUE);

    FLOW_INITIALIZE(&f);
    /* prevent L7 from kicking in */

    ssn.client.os_policy = OS_POLICY_LINUX;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.flow = &f;
    tcph.th_win = 5480;
    p.tcph = &tcph;
    p.ip4h = &ipv4h;
    p.tcpc = tcpc;
    p.tcpc.level4_comp_csum = -1;
    p.tcpvars = tcpvars;
    p.tcpvars.ts = &tcpopt;
    addr.s_addr = inet_addr("10.1.3.53");
    p.dst.address.address_un_data32[0] = addr.s_addr;
    addr1.s_addr = inet_addr("10.1.3.7");
    p.src.address.address_un_data32[0] = addr1.s_addr;
    f.protoctx = &ssn;
    stt.ra_ctx = ra_ctx;
    ssn.server = server;
    ssn.client = client;
    ssn.client.isn = 10;
    ssn.client.window = 5184;
    ssn.client.last_ack = 10;
    ssn.client.ra_base_seq = 10;
    ssn.client.next_win = 5184;
    ssn.server.isn = 1351079940;
    ssn.server.window = 5184;
    ssn.server.next_win = 1351088132;
    ssn.server.last_ack = 1351079940;
    ssn.server.ra_base_seq = 1351079940;

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 100;
    p.tcph->th_sum = 12345;

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(10);
    p.payload_len = 0;
    p.ip4h->ip_src = addr1;
    p.tcpc.ts1 = 10;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    ssn.flags |= STREAMTCP_FLAG_TIMESTAMP;
    tcph.th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_seq = htonl(1351079940);
    p.tcph->th_ack = htonl(11);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    tcph.th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.tcph->th_seq = htonl(11);
    p.tcph->th_ack = htonl(1351079941);
    p.payload_len = 0;
    p.tcpc.ts1 = 10;
    p.ip4h->ip_src = addr1;
    p.tcpc.level4_comp_csum = -1;
    p.tcph->th_sum = TCPCalculateChecksum((uint16_t *)&(p.ip4h->ip_src),
                                          (uint16_t *)p.tcph,
                                          (p.payload_len +
                                           p.tcpvars.hlen) );

    if (StreamTcp(&tv, &p, (void *)&stt, NULL, NULL) != TM_ECODE_OK) {
        printf("failed in segment reassmebling\n");
        result &= 0;
        goto end;
    }

    if (ssn.state != TCP_ESTABLISHED) {
        printf("the should have been changed to TCP_ESTABLISHED!!\n ");
        result &= 0;
        goto end;
    }

end:
    StreamTcpReturnStreamSegments(&ssn.client);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the initialization of tcp streams with ECN & CWR flags
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest32(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN | TH_CWR | TH_ECN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK | TH_ECN;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_ECN | TH_CWR;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.flowflags = FLOW_PKT_TOCLIENT;
    p.tcph->th_flags = TH_ACK;
    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }
    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the same
 *          ports have been used to start the new session after resetting the
 *          previous session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest33 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_RST | TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_CLOSED) {
        printf("Tcp session should have been closed\n");
        goto end;
    }

    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_SYN;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_seq = htonl(1);
    p.tcph->th_ack = htonl(2);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(2);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been ESTABLISHED\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the PUSH flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest34 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_PUSH;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been establisehd\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the allocation of TCP session for a given packet when the SYN
 *          packet is sent with the URG flag set.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest35 (void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    TcpReassemblyThreadCtx ra_ctx;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset(&ra_ctx, 0, sizeof(TcpReassemblyThreadCtx));
    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN|TH_URG;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;
    stt.ra_ctx = &ra_ctx;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1)
        goto end;

    if (((TcpSession *)(p.flow->protoctx))->state != TCP_ESTABLISHED) {
        printf("Tcp session should have been establisehd\n");
        goto end;
    }

    ret = 1;
end:
    StreamTcpSessionClear(p.flow->protoctx);
    StreamTcpFreeConfig(TRUE);
    return ret;
}

/**
 *  \test   Test the processing of PSH and URG flag in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest36(void)
{
    Packet p;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx(NULL);
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);
    stt.ra_ctx = ra_ctx;
    p.flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpInitConfig(TRUE);

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_flags = TH_SYN | TH_ACK;
    p.flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p.tcph->th_ack = htonl(1);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_ACK;
    p.flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }

    p.tcph->th_ack = htonl(2);
    p.tcph->th_seq = htonl(1);
    p.tcph->th_flags = TH_PUSH | TH_ACK | TH_URG;
    p.flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p.payload = payload;
    p.payload_len = 3;

    if (StreamTcpPacket(&tv, &p, &stt, &pq) == -1 || (TcpSession *)p.flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p.flow->protoctx)->client.next_seq != 4) {
        printf("the ssn->client.next_seq should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)p.flow->protoctx)->client.next_seq);
        goto end;
    }

    StreamTcpSessionClear(p.flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    return ret;
}
#endif

/**
 *  \test   Test the processing of out of order FIN packets in tcp session.
 *
 *  \retval On success it returns 1 and on failure 0.
 */
static int StreamTcpTest37(void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    int ret = 0;
    PacketQueueNoLock pq;
    memset(&pq,0,sizeof(PacketQueueNoLock));

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    FLOW_INITIALIZE(&f);

    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_ESTABLISHED) {
        printf("the TCP state should be TCP_ESTABLISEHD\n");
        goto end;
    }

    p->tcph->th_ack = htonl(2);
    p->tcph->th_seq = htonl(4);
    p->tcph->th_flags = TH_ACK|TH_FIN;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    if (((TcpSession *)p->flow->protoctx)->state != TCP_CLOSE_WAIT) {
        printf("the TCP state should be TCP_CLOSE_WAIT\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_ACK;
    p->payload_len = 0;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1 || (TcpSession *)p->flow->protoctx == NULL) {
        printf("failed in processing packet\n");
        goto end;
    }

    TcpStream *stream = &(((TcpSession *)p->flow->protoctx)->client);
    FAIL_IF(STREAM_RAW_PROGRESS(stream) != 0); // no detect no progress update

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest38 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[128];
    TCPHdr tcph;
    PacketQueueNoLock pq;

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&pq,0,sizeof(PacketQueueNoLock));

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpUTInit(&stt.ra_ctx);
    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(29847);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 1 as the previous sent ACK value is out of
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 1) {
        printf("the server.last_ack should be 1, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 127, 128); /*AAA*/
    p->payload = payload;
    p->payload_len = 127;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 128) {
        printf("the server.next_seq should be 128, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(256); // in window, but beyond next_seq
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256, as the previous sent ACK value
       is inside window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 1, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_ack = htonl(128);
    p->tcph->th_seq = htonl(8);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 256 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 256) {
        printf("the server.last_ack should be 256, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/**
 *  \test   Test the validation of the ACK number before setting up the
 *          stream.last_ack and update the next_seq after loosing the .
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int StreamTcpTest39 (void)
{
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    uint8_t payload[4];
    TCPHdr tcph;
    PacketQueueNoLock pq;

    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));
    memset(&pq,0,sizeof(PacketQueueNoLock));

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->tcph = &tcph;
    p->flowflags = FLOW_PKT_TOSERVER;
    int ret = 0;

    StreamTcpUTInit(&stt.ra_ctx);

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 4) {
        printf("the server.next_seq should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    p->tcph->th_ack = htonl(4);
    p->tcph->th_seq = htonl(2);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* last_ack value should be 4 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.last_ack != 4) {
        printf("the server.last_ack should be 4, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.last_ack);
        goto end;
    }

    p->tcph->th_seq = htonl(4);
    p->tcph->th_ack = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    StreamTcpCreateTestPacket(payload, 0x41, 3, 4); /*AAA*/
    p->payload = payload;
    p->payload_len = 3;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1) {
        printf("failed in processing packet in StreamTcpPacket\n");
        goto end;
    }

    /* next_seq value should be 2987 as the previous sent ACK value is inside
       window */
    if (((TcpSession *)(p->flow->protoctx))->server.next_seq != 7) {
        printf("the server.next_seq should be 7, but it is %"PRIu32"\n",
                ((TcpSession *)(p->flow->protoctx))->server.next_seq);
        goto end;
    }

    ret = 1;

end:
    StreamTcpSessionClear(p->flow->protoctx);
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick first */
static int StreamTcpTest42 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(501);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 500) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 500);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick second */
static int StreamTcpTest43 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, pick neither */
static int StreamTcpTest44 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(3001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_SYN_RECV) {
        SCLogDebug("state not TCP_SYN_RECV");
        goto end;
    }

    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    FLOW_DESTROY(&f);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

/** \test multiple different SYN/ACK, over the limit */
static int StreamTcpTest45 (void)
{
    int ret = 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread stt;
    TCPHdr tcph;
    PacketQueueNoLock pq;
    Packet *p = PacketGetFromAlloc();
    TcpSession *ssn;

    if (unlikely(p == NULL))
        return 0;

    memset(&pq,0,sizeof(PacketQueueNoLock));
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    memset(&stt, 0, sizeof (StreamTcpThread));
    memset(&tcph, 0, sizeof (TCPHdr));

    StreamTcpUTInit(&stt.ra_ctx);
    stream_config.max_synack_queued = 2;

    FLOW_INITIALIZE(&f);
    p->tcph = &tcph;
    tcph.th_win = htons(5480);
    p->flow = &f;

    /* SYN pkt */
    tcph.th_flags = TH_SYN;
    tcph.th_seq = htonl(100);
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(500);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(1000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(2000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    /* SYN/ACK */
    p->tcph->th_seq = htonl(3000);
    p->tcph->th_ack = htonl(101);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;

    if (StreamTcpPacket(&tv, p, &stt, &pq) != -1)
        goto end;

    /* ACK */
    p->tcph->th_ack = htonl(1001);
    p->tcph->th_seq = htonl(101);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;

    if (StreamTcpPacket(&tv, p, &stt, &pq) == -1)
        goto end;

    ssn = p->flow->protoctx;

    if (ssn->state != TCP_ESTABLISHED) {
        printf("state not TCP_ESTABLISHED: ");
        goto end;
    }

    if (ssn->server.isn != 1000) {
        SCLogDebug("ssn->server.isn %"PRIu32" != %"PRIu32"",
            ssn->server.isn, 1000);
        goto end;
    }
    if (ssn->client.isn != 100) {
        SCLogDebug("ssn->client.isn %"PRIu32" != %"PRIu32"",
            ssn->client.isn, 100);
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    SCFree(p);
    StreamTcpUTDeinit(stt.ra_ctx);
    return ret;
}

#endif /* UNITTESTS */

void StreamTcpRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamTcpTest01 -- TCP session allocation",
                   StreamTcpTest01);
    UtRegisterTest("StreamTcpTest02 -- TCP session deallocation",
                   StreamTcpTest02);
    UtRegisterTest("StreamTcpTest03 -- SYN missed MidStream session",
                   StreamTcpTest03);
    UtRegisterTest("StreamTcpTest04 -- SYN/ACK missed MidStream session",
                   StreamTcpTest04);
    UtRegisterTest("StreamTcpTest05 -- 3WHS missed MidStream session",
                   StreamTcpTest05);
    UtRegisterTest("StreamTcpTest06 -- FIN, RST message MidStream session",
                   StreamTcpTest06);
    UtRegisterTest("StreamTcpTest07 -- PAWS invalid timestamp",
                   StreamTcpTest07);
    UtRegisterTest("StreamTcpTest08 -- PAWS valid timestamp", StreamTcpTest08);
    UtRegisterTest("StreamTcpTest09 -- No Client Reassembly", StreamTcpTest09);
    UtRegisterTest("StreamTcpTest10 -- No missed packet Async stream",
                   StreamTcpTest10);
    UtRegisterTest("StreamTcpTest11 -- SYN missed Async stream",
                   StreamTcpTest11);
    UtRegisterTest("StreamTcpTest12 -- SYN/ACK missed Async stream",
                   StreamTcpTest12);
    UtRegisterTest("StreamTcpTest13 -- opposite stream packets for Async " "stream",
                   StreamTcpTest13);
    UtRegisterTest("StreamTcp4WHSTest01", StreamTcp4WHSTest01);
    UtRegisterTest("StreamTcp4WHSTest02", StreamTcp4WHSTest02);
    UtRegisterTest("StreamTcp4WHSTest03", StreamTcp4WHSTest03);
    UtRegisterTest("StreamTcpTest14 -- setup OS policy", StreamTcpTest14);
    UtRegisterTest("StreamTcpTest15 -- setup OS policy", StreamTcpTest15);
    UtRegisterTest("StreamTcpTest16 -- setup OS policy", StreamTcpTest16);
    UtRegisterTest("StreamTcpTest17 -- setup OS policy", StreamTcpTest17);
    UtRegisterTest("StreamTcpTest18 -- setup OS policy", StreamTcpTest18);
    UtRegisterTest("StreamTcpTest19 -- setup OS policy", StreamTcpTest19);
    UtRegisterTest("StreamTcpTest20 -- setup OS policy", StreamTcpTest20);
    UtRegisterTest("StreamTcpTest21 -- setup OS policy", StreamTcpTest21);
    UtRegisterTest("StreamTcpTest22 -- setup OS policy", StreamTcpTest22);
    UtRegisterTest("StreamTcpTest23 -- stream memory leaks", StreamTcpTest23);
    UtRegisterTest("StreamTcpTest24 -- stream memory leaks", StreamTcpTest24);
    UtRegisterTest("StreamTcpTest25 -- test ecn/cwr sessions",
                   StreamTcpTest25);
    UtRegisterTest("StreamTcpTest26 -- test ecn/cwr sessions",
                   StreamTcpTest26);
    UtRegisterTest("StreamTcpTest27 -- test ecn/cwr sessions",
                   StreamTcpTest27);
    UtRegisterTest("StreamTcpTest28 -- Memcap Test", StreamTcpTest28);

#if 0 /* VJ 2010/09/01 disabled since they blow up on Fedora and Fedora is
       * right about blowing up. The checksum functions are not used properly
       * in the tests. */
    UtRegisterTest("StreamTcpTest29 -- Badchecksum Reset Test", StreamTcpTest29, 1);
    UtRegisterTest("StreamTcpTest30 -- Badchecksum Overlap Test", StreamTcpTest30, 1);
    UtRegisterTest("StreamTcpTest31 -- MultipleSyns Test", StreamTcpTest31, 1);
    UtRegisterTest("StreamTcpTest32 -- Bogus CWR Test", StreamTcpTest32, 1);
    UtRegisterTest("StreamTcpTest33 -- RST-SYN Again Test", StreamTcpTest33, 1);
    UtRegisterTest("StreamTcpTest34 -- SYN-PUSH Test", StreamTcpTest34, 1);
    UtRegisterTest("StreamTcpTest35 -- SYN-URG Test", StreamTcpTest35, 1);
    UtRegisterTest("StreamTcpTest36 -- PUSH-URG Test", StreamTcpTest36, 1);
#endif
    UtRegisterTest("StreamTcpTest37 -- Out of order FIN Test",
                   StreamTcpTest37);

    UtRegisterTest("StreamTcpTest38 -- validate ACK", StreamTcpTest38);
    UtRegisterTest("StreamTcpTest39 -- update next_seq", StreamTcpTest39);

    UtRegisterTest("StreamTcpTest42 -- SYN/ACK queue", StreamTcpTest42);
    UtRegisterTest("StreamTcpTest43 -- SYN/ACK queue", StreamTcpTest43);
    UtRegisterTest("StreamTcpTest44 -- SYN/ACK queue", StreamTcpTest44);
    UtRegisterTest("StreamTcpTest45 -- SYN/ACK queue", StreamTcpTest45);

    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();

    StreamTcpSackRegisterTests ();
#endif /* UNITTESTS */
}
