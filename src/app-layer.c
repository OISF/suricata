/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Generic App-layer functions
 */

#include "suricata-common.h"
#include "suricata.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-expectation.h"
#include "app-layer-ftp.h"
#include "app-layer-detect-proto.h"
#include "app-layer-frames.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "stream-tcp-inline.h"
#include "stream-tcp.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-private.h"
#include "ippair.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "decode-events.h"
#include "app-layer-htp-mem.h"
#include "util-exception-policy.h"

/**
 * \brief This is for the app layer in general and it contains per thread
 *        context relevant to both the alpd and alp.
 */
struct AppLayerThreadCtx_ {
    /* App layer protocol detection thread context, from AppLayerProtoDetectGetCtxThread(). */
    AppLayerProtoDetectThreadCtx *alpd_tctx;
    /* App layer parser thread context, from AppLayerParserThreadCtxAlloc(). */
    AppLayerParserThreadCtx *alp_tctx;

#ifdef PROFILING
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
    AppProto alproto;
    uint64_t proto_detect_ticks_start;
    uint64_t proto_detect_ticks_end;
    uint64_t proto_detect_ticks_spent;
#endif
};

#define FLOW_PROTO_CHANGE_MAX_DEPTH 4096

#define MAX_COUNTER_SIZE 64
typedef struct AppLayerCounterNames_ {
    char name[MAX_COUNTER_SIZE];
    char tx_name[MAX_COUNTER_SIZE];
    char gap_error[MAX_COUNTER_SIZE];
    char parser_error[MAX_COUNTER_SIZE];
    char internal_error[MAX_COUNTER_SIZE];
    char alloc_error[MAX_COUNTER_SIZE];
} AppLayerCounterNames;

typedef struct AppLayerCounters_ {
    uint16_t counter_id;
    uint16_t counter_tx_id;
    uint16_t gap_error_id;
    uint16_t parser_error_id;
    uint16_t internal_error_id;
    uint16_t alloc_error_id;
} AppLayerCounters;

/* counter names. Only used at init. */
AppLayerCounterNames applayer_counter_names[FLOW_PROTO_APPLAYER_MAX][ALPROTO_MAX];
/* counter id's. Used that runtime. */
AppLayerCounters applayer_counters[FLOW_PROTO_APPLAYER_MAX][ALPROTO_MAX];

void AppLayerSetupCounters(void);
void AppLayerDeSetupCounters(void);

/***** L7 layer dispatchers *****/

static inline int ProtoDetectDone(const Flow *f, const TcpSession *ssn, uint8_t direction) {
    const TcpStream *stream = (direction & STREAM_TOSERVER) ? &ssn->client : &ssn->server;
    return ((stream->flags & STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_COMPLETED) ||
            (FLOW_IS_PM_DONE(f, direction) && FLOW_IS_PP_DONE(f, direction)));
}

/**
 * \note id can be 0 if protocol parser is disabled but detection
 *       is enabled.
 */
static void AppLayerIncFlowCounter(ThreadVars *tv, Flow *f)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].counter_id;
    if (likely(tv && id > 0)) {
        StatsIncr(tv, id);
    }
}

void AppLayerIncTxCounter(ThreadVars *tv, Flow *f, uint64_t step)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].counter_tx_id;
    if (likely(tv && id > 0)) {
        StatsAddUI64(tv, id, step);
    }
}

void AppLayerIncGapErrorCounter(ThreadVars *tv, Flow *f)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].gap_error_id;
    if (likely(tv && id > 0)) {
        StatsIncr(tv, id);
    }
}

void AppLayerIncAllocErrorCounter(ThreadVars *tv, Flow *f)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].alloc_error_id;
    if (likely(tv && id > 0)) {
        StatsIncr(tv, id);
    }
}

void AppLayerIncParserErrorCounter(ThreadVars *tv, Flow *f)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].parser_error_id;
    if (likely(tv && id > 0)) {
        StatsIncr(tv, id);
    }
}

void AppLayerIncInternalErrorCounter(ThreadVars *tv, Flow *f)
{
    const uint16_t id = applayer_counters[f->protomap][f->alproto].internal_error_id;
    if (likely(tv && id > 0)) {
        StatsIncr(tv, id);
    }
}

/* in IDS mode protocol detection is done in reverse order:
 * when TCP data is ack'd. We want to flag the correct packet,
 * so in this case we set a flag in the flow so that the first
 * packet in the correct direction can be tagged.
 *
 * For IPS we update packet and flow. */
static inline void FlagPacketFlow(Packet *p, Flow *f, uint8_t flags)
{
    if (p->proto != IPPROTO_TCP || EngineModeIsIPS()) {
        if (flags & STREAM_TOSERVER) {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                p->flags |= PKT_PROTO_DETECT_TS_DONE;
                f->flags |= FLOW_PROTO_DETECT_TS_DONE;
            } else {
                f->flags |= FLOW_PROTO_DETECT_TS_DONE;
            }
        } else {
            if (p->flowflags & FLOW_PKT_TOCLIENT) {
                p->flags |= PKT_PROTO_DETECT_TC_DONE;
                f->flags |= FLOW_PROTO_DETECT_TC_DONE;
            } else {
                f->flags |= FLOW_PROTO_DETECT_TC_DONE;
            }
        }
    } else {
        if (flags & STREAM_TOSERVER) {
            f->flags |= FLOW_PROTO_DETECT_TS_DONE;
        } else {
            f->flags |= FLOW_PROTO_DETECT_TC_DONE;
        }
    }
}

static void DisableAppLayer(ThreadVars *tv, Flow *f, Packet *p)
{
    SCLogDebug("disable app layer for flow %p alproto %u ts %u tc %u",
            f, f->alproto, f->alproto_ts, f->alproto_tc);
    FlowCleanupAppLayer(f);
    StreamTcpDisableAppLayer(f);
    TcpSession *ssn = f->protoctx;
    ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;
    f->alproto = ALPROTO_FAILED;
    AppLayerIncFlowCounter(tv, f);

    if (f->alproto_tc != ALPROTO_FAILED) {
        if (f->alproto_tc == ALPROTO_UNKNOWN) {
            f->alproto_tc = ALPROTO_FAILED;
        }
        FlagPacketFlow(p, f, STREAM_TOCLIENT);
    }
    if (f->alproto_ts != ALPROTO_FAILED) {
        if (f->alproto_ts == ALPROTO_UNKNOWN) {
            f->alproto_ts = ALPROTO_FAILED;
        }
        FlagPacketFlow(p, f, STREAM_TOSERVER);
    }
    SCLogDebug("disabled app layer for flow %p alproto %u ts %u tc %u",
            f, f->alproto, f->alproto_ts, f->alproto_tc);
}

/* See if we're going to have to give up:
 *
 * If we're getting a lot of data in one direction and the
 * proto for this direction is unknown, proto detect will
 * hold up segments in the segment list in the stream.
 * They are held so that if we detect the protocol on the
 * opposing stream, we can still parse this side of the stream
 * as well. However, some sessions are very unbalanced. FTP
 * data channels, large PUT/POST request and many others, can
 * lead to cases where we would have to store many megabytes
 * worth of segments before we see the opposing stream. This
 * leads to risks of resource starvation.
 *
 * Here a cutoff point is enforced. If we've stored 100k in
 * one direction and we've seen no data in the other direction,
 * we give up.
 *
 * Giving up means we disable applayer an set an applayer event
 */
static void TCPProtoDetectCheckBailConditions(ThreadVars *tv,
        Flow *f, TcpSession *ssn, Packet *p)
{
    if (ssn->state < TCP_ESTABLISHED) {
        SCLogDebug("skip as long as TCP is not ESTABLISHED (TCP fast open)");
        return;
    }

    const uint32_t size_ts = StreamDataAvailableForProtoDetect(&ssn->client);
    const uint32_t size_tc = StreamDataAvailableForProtoDetect(&ssn->server);
    SCLogDebug("size_ts %" PRIu32 ", size_tc %" PRIu32, size_ts, size_tc);

    /* at least 100000 whatever the conditions
     * and can be more if window is bigger and if configuration allows it */
    const uint32_t size_tc_limit =
            MAX(100000, MIN(ssn->client.window, stream_config.reassembly_depth));
    const uint32_t size_ts_limit =
            MAX(100000, MIN(ssn->server.window, stream_config.reassembly_depth));

    if (ProtoDetectDone(f, ssn, STREAM_TOSERVER) &&
        ProtoDetectDone(f, ssn, STREAM_TOCLIENT))
    {
        goto failure;

        /* we bail out whatever the pp and pm states if
         * we received too much data */
    } else if (size_tc > 2 * size_tc_limit || size_ts > 2 * size_ts_limit) {
        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events, APPLAYER_PROTO_DETECTION_SKIPPED);
        goto failure;

    } else if (FLOW_IS_PM_DONE(f, STREAM_TOSERVER) && FLOW_IS_PP_DONE(f, STREAM_TOSERVER) &&
               size_ts > size_ts_limit && size_tc == 0) {
        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
        goto failure;

    } else if (FLOW_IS_PM_DONE(f, STREAM_TOCLIENT) && FLOW_IS_PP_DONE(f, STREAM_TOCLIENT) &&
               size_tc > size_tc_limit && size_ts == 0) {
        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
        goto failure;

    /* little data in ts direction, pp done, pm not done (max
     * depth not reached), ts direction done, lots of data in
     * tc direction. */
    } else if (size_tc > size_tc_limit && FLOW_IS_PP_DONE(f, STREAM_TOSERVER) &&
               !(FLOW_IS_PM_DONE(f, STREAM_TOSERVER)) && FLOW_IS_PM_DONE(f, STREAM_TOCLIENT) &&
               FLOW_IS_PP_DONE(f, STREAM_TOCLIENT)) {
        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
        goto failure;

    /* little data in tc direction, pp done, pm not done (max
     * depth not reached), tc direction done, lots of data in
     * ts direction. */
    } else if (size_ts > size_ts_limit && FLOW_IS_PP_DONE(f, STREAM_TOCLIENT) &&
               !(FLOW_IS_PM_DONE(f, STREAM_TOCLIENT)) && FLOW_IS_PM_DONE(f, STREAM_TOSERVER) &&
               FLOW_IS_PP_DONE(f, STREAM_TOSERVER)) {
        AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                APPLAYER_PROTO_DETECTION_SKIPPED);
        goto failure;
    }
    return;

failure:
    DisableAppLayer(tv, f, p);
    return;
}

static int TCPProtoDetectTriggerOpposingSide(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
        Packet *p, TcpSession *ssn, const TcpStream *stream)
{
    TcpStream *opposing_stream = NULL;
    if (stream == &ssn->client) {
        opposing_stream = &ssn->server;
    } else {
        opposing_stream = &ssn->client;
    }

    /* if the opposing side is not going to work, then
     * we just have to give up. */
    if (opposing_stream->flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) {
        SCLogDebug("opposing dir has STREAMTCP_STREAM_FLAG_NOREASSEMBLY set");
        return -1;
    }

    enum StreamUpdateDir dir = StreamTcpInlineMode() ?
                                                UPDATE_DIR_OPPOSING :
                                                UPDATE_DIR_PACKET;
    int ret = StreamTcpReassembleAppLayer(tv, ra_ctx, ssn,
            opposing_stream, p, dir);
    return ret;
}

extern enum ExceptionPolicy g_applayerparser_error_policy;

/** \todo data const
 *  \retval int -1 error
 *  \retval int 0 ok
 */
static int TCPProtoDetect(ThreadVars *tv,
        TcpReassemblyThreadCtx *ra_ctx, AppLayerThreadCtx *app_tctx,
        Packet *p, Flow *f, TcpSession *ssn, TcpStream **stream,
        uint8_t *data, uint32_t data_len, uint8_t flags)
{
    AppProto *alproto;
    AppProto *alproto_otherdir;
    uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;

    if (flags & STREAM_TOSERVER) {
        alproto = &f->alproto_ts;
        alproto_otherdir = &f->alproto_tc;
    } else {
        alproto = &f->alproto_tc;
        alproto_otherdir = &f->alproto_ts;
    }

    SCLogDebug("Stream initializer (len %" PRIu32 ")", data_len);
#ifdef PRINT
    if (data_len > 0) {
        printf("=> Init Stream Data (app layer) -- start %s%s\n",
                flags & STREAM_TOCLIENT ? "toclient" : "",
                flags & STREAM_TOSERVER ? "toserver" : "");
        PrintRawDataFp(stdout, data, data_len);
        printf("=> Init Stream Data -- end\n");
    }
#endif

    bool reverse_flow = false;
    DEBUG_VALIDATE_BUG_ON(data == NULL && data_len > 0);
    PACKET_PROFILING_APP_PD_START(app_tctx);
    *alproto = AppLayerProtoDetectGetProto(app_tctx->alpd_tctx,
            f, data, data_len,
            IPPROTO_TCP, flags, &reverse_flow);
    PACKET_PROFILING_APP_PD_END(app_tctx);
    SCLogDebug("alproto %u rev %s", *alproto, reverse_flow ? "true" : "false");

    if (*alproto != ALPROTO_UNKNOWN) {
        if (*alproto_otherdir != ALPROTO_UNKNOWN && *alproto_otherdir != *alproto) {
            AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                    APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS);

            if (ssn->data_first_seen_dir == APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
                /* if we already invoked the parser, we go with that proto */
                f->alproto = *alproto_otherdir;
            } else {
                /* no data sent to parser yet, we can still choose
                 * we're trusting the server more. */
                if (flags & STREAM_TOCLIENT)
                    f->alproto = *alproto;
                else
                    f->alproto = *alproto_otherdir;
            }
        } else {
            f->alproto = *alproto;
        }

        StreamTcpSetStreamFlagAppProtoDetectionCompleted(*stream);
        TcpSessionSetReassemblyDepth(ssn,
                AppLayerParserGetStreamDepth(f));
        FlagPacketFlow(p, f, flags);

        /* if protocol detection indicated that we need to reverse
         * the direction of the flow, do it now. We flip the flow,
         * packet and the direction flags */
        if (reverse_flow &&
                ((ssn->flags & (STREAMTCP_FLAG_MIDSTREAM | STREAMTCP_FLAG_MIDSTREAM_SYNACK)) ==
                        STREAMTCP_FLAG_MIDSTREAM)) {
            /* but only if we didn't already detect it on the other side. */
            if (*alproto_otherdir == ALPROTO_UNKNOWN) {
                SCLogDebug("reversing flow after proto detect told us so");
                PacketSwap(p);
                FlowSwap(f);
                SWAP_FLAGS(flags, STREAM_TOSERVER, STREAM_TOCLIENT);
                if (*stream == &ssn->client) {
                    *stream = &ssn->server;
                } else {
                    *stream = &ssn->client;
                }
                direction = 1 - direction;
            } else {
                // TODO event, error?
            }
        }

        /* account flow if we have both sides */
        if (*alproto_otherdir != ALPROTO_UNKNOWN) {
            AppLayerIncFlowCounter(tv, f);
        }

        /* if we have seen data from the other direction first, send
         * data for that direction first to the parser.  This shouldn't
         * be an issue, since each stream processing happens
         * independently of the other stream direction.  At this point of
         * call, you need to know that this function's already being
         * called by the very same StreamReassembly() function that we
         * will now call shortly for the opposing direction. */
        if ((ssn->data_first_seen_dir & (STREAM_TOSERVER | STREAM_TOCLIENT)) &&
                !(flags & ssn->data_first_seen_dir))
        {
            SCLogDebug("protocol %s needs first data in other direction",
                    AppProtoToString(*alproto));

            if (TCPProtoDetectTriggerOpposingSide(tv, ra_ctx,
                        p, ssn, *stream) != 0)
            {
                goto detect_error;
            }
            if (FlowChangeProto(f)) {
                /* We have the first data which requested a protocol change from P1 to P2
                 * even if it was not recognized at first as being P1
                 * As the second data was recognized as P1, the protocol did not change !
                 */
                FlowUnsetChangeProtoFlag(f);
                AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                                                 APPLAYER_UNEXPECTED_PROTOCOL);
            }
        }

        /* if the parser operates such that it needs to see data from
         * a particular direction first, we check if we have seen
         * data from that direction first for the flow.  IF it is not
         * the same, we set an event and exit.
         *
         * \todo We need to figure out a more robust solution for this,
         *       as this can lead to easy evasion tactics, where the
         *       attackeer can first send some dummy data in the wrong
         *       direction first to mislead our proto detection process.
         *       While doing this we need to update the parsers as well,
         *       since the parsers must be robust to see such wrong
         *       direction data.
         *       Either ways the moment we see the
         *       APPLAYER_WRONG_DIRECTION_FIRST_DATA event set for the
         *       flow, it shows something's fishy.
         */
        if (ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
            uint8_t first_data_dir;
            first_data_dir = AppLayerParserGetFirstDataDir(f->proto, f->alproto);

            if (first_data_dir && !(first_data_dir & ssn->data_first_seen_dir)) {
                AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                        APPLAYER_WRONG_DIRECTION_FIRST_DATA);
                goto detect_error;
            }
            /* This can happen if the current direction is not the
             * right direction, and the data from the other(also
             * the right direction) direction is available to be sent
             * to the app layer, but it is not ack'ed yet and hence
             * the forced call to STreamTcpAppLayerReassemble still
             * hasn't managed to send data from the other direction
             * to the app layer. */
            if (first_data_dir && !(first_data_dir & flags)) {
                FlowCleanupAppLayer(f);
                StreamTcpResetStreamFlagAppProtoDetectionCompleted(*stream);
                FLOW_RESET_PP_DONE(f, flags);
                FLOW_RESET_PM_DONE(f, flags);
                FLOW_RESET_PE_DONE(f, flags);
                SCReturnInt(-1);
            }
        }

        /* Set a value that is neither STREAM_TOSERVER, nor STREAM_TOCLIENT */
        ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;

        /* finally, invoke the parser */
        PACKET_PROFILING_APP_START(app_tctx, f->alproto);
        int r = AppLayerParserParse(tv, app_tctx->alp_tctx, f, f->alproto,
                flags, data, data_len);
        PACKET_PROFILING_APP_END(app_tctx, f->alproto);
        p->flags |= PKT_APPLAYER_UPDATE;
        if (r != 1) {
            StreamTcpUpdateAppLayerProgress(ssn, direction, data_len);
        }
        if (r < 0) {
            goto parser_error;
        }
    } else {
        /* if the ssn is midstream, we may end up with a case where the
         * start of an HTTP request is missing. We won't detect HTTP based
         * on the request. However, the reply is fine, so we detect
         * HTTP anyway. This leads to passing the incomplete request to
         * the htp parser.
         *
         * This has been observed, where the http parser then saw many
         * bogus requests in the incomplete data.
         *
         * To counter this case, a midstream session MUST find it's
         * protocol in the toserver direction. If not, we assume the
         * start of the request/toserver is incomplete and no reliable
         * detection and parsing is possible. So we give up.
         */
        if ((ssn->flags & STREAMTCP_FLAG_MIDSTREAM) &&
                !(ssn->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK))
        {
            if (FLOW_IS_PM_DONE(f, STREAM_TOSERVER) && FLOW_IS_PP_DONE(f, STREAM_TOSERVER)) {
                SCLogDebug("midstream end pd %p", ssn);
                /* midstream and toserver detection failed: give up */
                DisableAppLayer(tv, f, p);
                SCReturnInt(0);
            }
        }

        if (*alproto_otherdir != ALPROTO_UNKNOWN) {
            uint8_t first_data_dir;
            first_data_dir = AppLayerParserGetFirstDataDir(f->proto, *alproto_otherdir);

            /* this would handle this test case -
             * http parser which says it wants to see toserver data first only.
             * tcp handshake
             * toclient data first received. - RUBBISH DATA which
             *                                 we don't detect as http
             * toserver data next sent - we detect this as http.
             * at this stage we see that toclient is the first data seen
             * for this session and we try and redetect the app protocol,
             * but we are unable to detect the app protocol like before.
             * But since we have managed to detect the protocol for the
             * other direction as http, we try to use that.  At this
             * stage we check if the direction of this stream matches
             * to that acceptable by the app parser.  If it is not the
             * acceptable direction we error out.
             */
            if ((ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) &&
                    (first_data_dir) && !(first_data_dir & flags))
            {
                goto detect_error;
            }

            /* if protocol detection is marked done for our direction we
             * pass our data on. We're only succeeded in finding one
             * direction: the opposing stream
             *
             * If PD was not yet complete, we don't do anything.
             */
            if (FLOW_IS_PM_DONE(f, flags) && FLOW_IS_PP_DONE(f, flags)) {
                if (data_len > 0)
                    ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;

                if (*alproto_otherdir != ALPROTO_FAILED) {
                    PACKET_PROFILING_APP_START(app_tctx, f->alproto);
                    int r = AppLayerParserParse(tv, app_tctx->alp_tctx, f,
                            f->alproto, flags,
                            data, data_len);
                    PACKET_PROFILING_APP_END(app_tctx, f->alproto);
                    p->flags |= PKT_APPLAYER_UPDATE;
                    if (r != 1) {
                        StreamTcpUpdateAppLayerProgress(ssn, direction, data_len);
                    }

                    AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                            APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION);
                    TcpSessionSetReassemblyDepth(ssn,
                            AppLayerParserGetStreamDepth(f));

                    *alproto = *alproto_otherdir;
                    SCLogDebug("packet %"PRIu64": pd done(us %u them %u), parser called (r==%d), APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION set",
                            p->pcap_cnt, *alproto, *alproto_otherdir, r);
                    if (r < 0) {
                        goto parser_error;
                    }
                }
                *alproto = ALPROTO_FAILED;
                StreamTcpSetStreamFlagAppProtoDetectionCompleted(*stream);
                AppLayerIncFlowCounter(tv, f);
                FlagPacketFlow(p, f, flags);

            }
        } else {
            /* both sides unknown, let's see if we need to give up */
            if (FlowChangeProto(f)) {
                /* TCPProtoDetectCheckBailConditions does not work well because
                 * size_tc from STREAM_RIGHT_EDGE is not reset to zero
                 * so, we set a lower limit to the data we inspect
                 * We could instead have set ssn->server.sb.stream_offset = 0;
                 */
                if (data_len >= FLOW_PROTO_CHANGE_MAX_DEPTH || (flags & STREAM_EOF)) {
                    DisableAppLayer(tv, f, p);
                }
            } else {
                TCPProtoDetectCheckBailConditions(tv, f, ssn, p);
            }
        }
    }
    SCReturnInt(0);
parser_error:
    ExceptionPolicyApply(p, g_applayerparser_error_policy, PKT_DROP_REASON_APPLAYER_ERROR);
    SCReturnInt(-1);
detect_error:
    DisableAppLayer(tv, f, p);
    SCReturnInt(-2);
}

/** \brief handle TCP data for the app-layer.
 *
 *  First run protocol detection and then when the protocol is known invoke
 *  the app layer parser.
 *
 *  \param stream ptr-to-ptr to stream object. Might change if flow dir is
 *                reversed.
 */
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                          Packet *p, Flow *f,
                          TcpSession *ssn, TcpStream **stream,
                          uint8_t *data, uint32_t data_len,
                          uint8_t flags)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);
    DEBUG_VALIDATE_BUG_ON(data_len > (uint32_t)INT_MAX);

    AppLayerThreadCtx *app_tctx = ra_ctx->app_tctx;
    AppProto alproto;
    int r = 0;

    SCLogDebug("data_len %u flags %02X", data_len, flags);
    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        SCLogDebug("STREAMTCP_FLAG_APP_LAYER_DISABLED is set");
        goto end;
    }

    const uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;

    if (flags & STREAM_TOSERVER) {
        alproto = f->alproto_ts;
    } else {
        alproto = f->alproto_tc;
    }

    /* If a gap notification, relay the notification on to the
     * app-layer if known. */
    if (flags & STREAM_GAP) {
        if (alproto == ALPROTO_UNKNOWN) {
            StreamTcpSetStreamFlagAppProtoDetectionCompleted(*stream);
            SCLogDebug("ALPROTO_UNKNOWN flow %p, due to GAP in stream start", f);
            /* if the other side didn't already find the proto, we're done */
            if (f->alproto == ALPROTO_UNKNOWN) {
                goto failure;
            }
        }
        if (FlowChangeProto(f)) {
            FlowUnsetChangeProtoFlag(f);
            SCLogDebug("Cannot handle gap while changing protocol");
            goto failure;
        }
        PACKET_PROFILING_APP_START(app_tctx, f->alproto);
        r = AppLayerParserParse(tv, app_tctx->alp_tctx, f, f->alproto,
                flags, data, data_len);
        PACKET_PROFILING_APP_END(app_tctx, f->alproto);
        p->flags |= PKT_APPLAYER_UPDATE;
        /* ignore parser result for gap */
        StreamTcpUpdateAppLayerProgress(ssn, direction, data_len);
        if (r < 0) {
            ExceptionPolicyApply(p, g_applayerparser_error_policy, PKT_DROP_REASON_APPLAYER_ERROR);
            SCReturnInt(-1);
        }
        goto end;
    }

    /* if we don't know the proto yet and we have received a stream
     * initializer message, we run proto detection.
     * We receive 2 stream init msgs (one for each direction), we
     * only run the proto detection for both and emit an event
     * in the case protocols mismatch. */
    if (alproto == ALPROTO_UNKNOWN && (flags & STREAM_START)) {
        DEBUG_VALIDATE_BUG_ON(FlowChangeProto(f));
        /* run protocol detection */
        if (TCPProtoDetect(tv, ra_ctx, app_tctx, p, f, ssn, stream,
                           data, data_len, flags) != 0) {
            goto failure;
        }
    } else if (alproto != ALPROTO_UNKNOWN && FlowChangeProto(f)) {
        SCLogDebug("protocol change, old %s", AppProtoToString(f->alproto_orig));
        void *alstate_orig = f->alstate;
        AppLayerParserState *alparser = f->alparser;
        // we delay AppLayerParserStateCleanup because we may need previous parser state
        AppLayerProtoDetectReset(f);
        StreamTcpResetStreamFlagAppProtoDetectionCompleted(&ssn->client);
        StreamTcpResetStreamFlagAppProtoDetectionCompleted(&ssn->server);
        /* rerun protocol detection */
        int rd = TCPProtoDetect(tv, ra_ctx, app_tctx, p, f, ssn, stream, data, data_len, flags);
        if (f->alproto == ALPROTO_UNKNOWN) {
            DEBUG_VALIDATE_BUG_ON(alstate_orig != f->alstate);
            // not enough data, revert AppLayerProtoDetectReset to rerun detection
            f->alparser = alparser;
            f->alproto = f->alproto_orig;
            f->alproto_tc = f->alproto_orig;
            f->alproto_ts = f->alproto_orig;
        } else {
            FlowUnsetChangeProtoFlag(f);
            AppLayerParserStateProtoCleanup(f->protomap, f->alproto_orig, alstate_orig, alparser);
            if (alstate_orig == f->alstate) {
                // we just freed it
                f->alstate = NULL;
            }
        }
        if (rd != 0) {
            SCLogDebug("proto detect failure");
            goto failure;
        }
        SCLogDebug("protocol change, old %s, new %s",
                AppProtoToString(f->alproto_orig), AppProtoToString(f->alproto));

        if (f->alproto_expect != ALPROTO_UNKNOWN && f->alproto != ALPROTO_UNKNOWN &&
                f->alproto != f->alproto_expect) {
            AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                                             APPLAYER_UNEXPECTED_PROTOCOL);

            if (f->alproto_expect == ALPROTO_TLS && f->alproto != ALPROTO_TLS) {
                AppLayerDecoderEventsSetEventRaw(&p->app_layer_events,
                        APPLAYER_NO_TLS_AFTER_STARTTLS);

            }
        }
    } else {
        SCLogDebug("stream data (len %" PRIu32 " alproto "
                   "%"PRIu16" (flow %p)", data_len, f->alproto, f);
#ifdef PRINT
        if (data_len > 0) {
            printf("=> Stream Data (app layer) -- start %s%s\n",
                   flags & STREAM_TOCLIENT ? "toclient" : "",
                   flags & STREAM_TOSERVER ? "toserver" : "");
            PrintRawDataFp(stdout, data, data_len);
            printf("=> Stream Data -- end\n");
        }
#endif
        /* if we don't have a data object here we are not getting it
         * a start msg should have gotten us one */
        if (f->alproto != ALPROTO_UNKNOWN) {
            PACKET_PROFILING_APP_START(app_tctx, f->alproto);
            r = AppLayerParserParse(tv, app_tctx->alp_tctx, f, f->alproto,
                                    flags, data, data_len);
            PACKET_PROFILING_APP_END(app_tctx, f->alproto);
            p->flags |= PKT_APPLAYER_UPDATE;
            if (r != 1) {
                StreamTcpUpdateAppLayerProgress(ssn, direction, data_len);
                if (r < 0) {
                    ExceptionPolicyApply(
                            p, g_applayerparser_error_policy, PKT_DROP_REASON_APPLAYER_ERROR);
                    SCReturnInt(-1);
                }
            }
        }
    }

    goto end;
 failure:
    r = -1;
 end:
    SCReturnInt(r);
}

/**
 *  \brief Handle a app layer UDP message
 *
 *  If the protocol is yet unknown, the proto detection code is run first.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param f *locked* flow
 *  \param p UDP packet
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleUdp(ThreadVars *tv, AppLayerThreadCtx *tctx, Packet *p, Flow *f)
{
    SCEnter();
    AppProto *alproto;
    AppProto *alproto_otherdir;

    if (f->alproto_ts == ALPROTO_FAILED && f->alproto_tc == ALPROTO_FAILED) {
        SCReturnInt(0);
    }

    int r = 0;
    uint8_t flags = 0;
    if (p->flowflags & FLOW_PKT_TOSERVER) {
        flags |= STREAM_TOSERVER;
        alproto = &f->alproto_ts;
        alproto_otherdir = &f->alproto_tc;
    } else {
        flags |= STREAM_TOCLIENT;
        alproto = &f->alproto_tc;
        alproto_otherdir = &f->alproto_ts;
    }

    AppLayerProfilingReset(tctx);

    /* if the protocol is still unknown, run detection */
    if (*alproto == ALPROTO_UNKNOWN) {
        SCLogDebug("Detecting AL proto on udp mesg (len %" PRIu32 ")",
                   p->payload_len);

        bool reverse_flow = false;
        PACKET_PROFILING_APP_PD_START(tctx);
        *alproto = AppLayerProtoDetectGetProto(
                tctx->alpd_tctx, f, p->payload, p->payload_len, IPPROTO_UDP, flags, &reverse_flow);
        PACKET_PROFILING_APP_PD_END(tctx);

        switch (*alproto) {
            case ALPROTO_UNKNOWN:
                if (*alproto_otherdir != ALPROTO_UNKNOWN) {
                    // Use recognized side
                    f->alproto = *alproto_otherdir;
                    // do not keep ALPROTO_UNKNOWN for this side so as not to loop
                    *alproto = *alproto_otherdir;
                    if (*alproto_otherdir == ALPROTO_FAILED) {
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
                    }
                } else {
                    // First side of protocol is unknown
                    *alproto = ALPROTO_FAILED;
                }
                break;
            case ALPROTO_FAILED:
                if (*alproto_otherdir != ALPROTO_UNKNOWN) {
                    // Use recognized side
                    f->alproto = *alproto_otherdir;
                    if (*alproto_otherdir == ALPROTO_FAILED) {
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
                    }
                }
                // else wait for second side of protocol
                break;
            default:
                if (*alproto_otherdir != ALPROTO_UNKNOWN && *alproto_otherdir != ALPROTO_FAILED) {
                    if (*alproto_otherdir != *alproto) {
                        AppLayerDecoderEventsSetEventRaw(
                                &p->app_layer_events, APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS);
                        // data already sent to parser, we cannot change the protocol to use the one
                        // of the server
                    }
                } else {
                    f->alproto = *alproto;
                }
        }
        if (*alproto_otherdir == ALPROTO_UNKNOWN) {
            if (f->alproto == ALPROTO_UNKNOWN) {
                // so as to increase stat about .app_layer.flow.failed_udp
                f->alproto = ALPROTO_FAILED;
            }
            // If the other side is unknown, this is the first packet of the flow
            AppLayerIncFlowCounter(tv, f);
        }

        // parse the data if we recognized one protocol
        if (f->alproto != ALPROTO_UNKNOWN && f->alproto != ALPROTO_FAILED) {
            if (reverse_flow) {
                SCLogDebug("reversing flow after proto detect told us so");
                PacketSwap(p);
                FlowSwap(f);
                SWAP_FLAGS(flags, STREAM_TOSERVER, STREAM_TOCLIENT);
            }

            PACKET_PROFILING_APP_START(tctx, f->alproto);
            r = AppLayerParserParse(tv, tctx->alp_tctx, f, f->alproto,
                                    flags, p->payload, p->payload_len);
            PACKET_PROFILING_APP_END(tctx, f->alproto);
            p->flags |= PKT_APPLAYER_UPDATE;
        }
        PACKET_PROFILING_APP_STORE(tctx, p);
        /* we do only inspection in one direction, so flag both
         * sides as done here */
        FlagPacketFlow(p, f, STREAM_TOSERVER);
        FlagPacketFlow(p, f, STREAM_TOCLIENT);
    } else {
        SCLogDebug("data (len %" PRIu32 " ), alproto "
                   "%"PRIu16" (flow %p)", p->payload_len, f->alproto, f);

        /* run the parser */
        PACKET_PROFILING_APP_START(tctx, f->alproto);
        r = AppLayerParserParse(tv, tctx->alp_tctx, f, f->alproto,
                flags, p->payload, p->payload_len);
        PACKET_PROFILING_APP_END(tctx, f->alproto);
        PACKET_PROFILING_APP_STORE(tctx, p);
        p->flags |= PKT_APPLAYER_UPDATE;
    }
    if (r < 0) {
        ExceptionPolicyApply(p, g_applayerparser_error_policy, PKT_DROP_REASON_APPLAYER_ERROR);
        SCReturnInt(-1);
    }

    SCReturnInt(r);
}

/***** Utility *****/

AppProto AppLayerGetProtoByName(char *alproto_name)
{
    SCEnter();
    AppProto r = AppLayerProtoDetectGetProtoByName(alproto_name);
    SCReturnCT(r, "AppProto");
}

const char *AppLayerGetProtoName(AppProto alproto)
{
    SCEnter();
    const char * r = AppLayerProtoDetectGetProtoName(alproto);
    SCReturnCT(r, "char *");
}

void AppLayerListSupportedProtocols(void)
{
    SCEnter();

    AppProto alproto;
    AppProto alprotos[ALPROTO_MAX];

    AppLayerProtoDetectSupportedAppProtocols(alprotos);

    printf("=========Supported App Layer Protocols=========\n");
    for (alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        if (alprotos[alproto] == 1)
            printf("%s\n", AppLayerGetProtoName(alproto));
    }

    SCReturn;
}

/***** Setup/General Registration *****/

int AppLayerSetup(void)
{
    SCEnter();

    AppLayerProtoDetectSetup();
    AppLayerParserSetup();

    AppLayerParserRegisterProtocolParsers();
    AppLayerProtoDetectPrepareState();

    AppLayerSetupCounters();

    SCReturnInt(0);
}

int AppLayerDeSetup(void)
{
    SCEnter();

    AppLayerProtoDetectDeSetup();
    AppLayerParserDeSetup();

    AppLayerDeSetupCounters();

    SCReturnInt(0);
}

AppLayerThreadCtx *AppLayerGetCtxThread(ThreadVars *tv)
{
    SCEnter();

    AppLayerThreadCtx *app_tctx = SCMalloc(sizeof(*app_tctx));
    if (app_tctx == NULL)
        goto error;
    memset(app_tctx, 0, sizeof(*app_tctx));

    if ((app_tctx->alpd_tctx = AppLayerProtoDetectGetCtxThread()) == NULL)
        goto error;
    if ((app_tctx->alp_tctx = AppLayerParserThreadCtxAlloc()) == NULL)
        goto error;

    goto done;
 error:
    AppLayerDestroyCtxThread(app_tctx);
    app_tctx = NULL;
 done:
    SCReturnPtr(app_tctx, "void *");
}

void AppLayerDestroyCtxThread(AppLayerThreadCtx *app_tctx)
{
    SCEnter();

    if (app_tctx == NULL)
        SCReturn;

    if (app_tctx->alpd_tctx != NULL)
        AppLayerProtoDetectDestroyCtxThread(app_tctx->alpd_tctx);
    if (app_tctx->alp_tctx != NULL)
        AppLayerParserThreadCtxFree(app_tctx->alp_tctx);
    SCFree(app_tctx);

    SCReturn;
}

#ifdef PROFILING
void AppLayerProfilingResetInternal(AppLayerThreadCtx *app_tctx)
{
    PACKET_PROFILING_APP_RESET(app_tctx);
}

void AppLayerProfilingStoreInternal(AppLayerThreadCtx *app_tctx, Packet *p)
{
    PACKET_PROFILING_APP_STORE(app_tctx, p);
}
#endif

/** \brief HACK to work around our broken unix manager (re)init loop
 */
void AppLayerRegisterGlobalCounters(void)
{
    StatsRegisterGlobalCounter("http.memuse", HTPMemuseGlobalCounter);
    StatsRegisterGlobalCounter("http.memcap", HTPMemcapGlobalCounter);
    StatsRegisterGlobalCounter("ftp.memuse", FTPMemuseGlobalCounter);
    StatsRegisterGlobalCounter("ftp.memcap", FTPMemcapGlobalCounter);
    StatsRegisterGlobalCounter("app_layer.expectations", ExpectationGetCounter);
}

#define IPPROTOS_MAX 2
void AppLayerSetupCounters()
{
    const uint8_t ipprotos[] = { IPPROTO_TCP, IPPROTO_UDP };
    AppProto alprotos[ALPROTO_MAX];
    const char *str = "app_layer.flow.";
    const char *estr = "app_layer.error.";

    AppLayerProtoDetectSupportedAppProtocols(alprotos);

    for (uint8_t p = 0; p < IPPROTOS_MAX; p++) {
        const uint8_t ipproto = ipprotos[p];
        const uint8_t ipproto_map = FlowGetProtoMapping(ipproto);
        const uint8_t other_ipproto = ipproto == IPPROTO_TCP ? IPPROTO_UDP : IPPROTO_TCP;
        const char *ipproto_suffix = (ipproto == IPPROTO_TCP) ? "_tcp" : "_udp";

        for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            if (alprotos[alproto] == 1) {
                const char *tx_str = "app_layer.tx.";
                const char *alproto_str = AppLayerGetProtoName(alproto);

                if (AppLayerParserProtoIsRegistered(ipproto, alproto) &&
                        AppLayerParserProtoIsRegistered(other_ipproto, alproto)) {
                    snprintf(applayer_counter_names[ipproto_map][alproto].name,
                            sizeof(applayer_counter_names[ipproto_map][alproto].name),
                            "%s%s%s", str, alproto_str, ipproto_suffix);
                    snprintf(applayer_counter_names[ipproto_map][alproto].tx_name,
                            sizeof(applayer_counter_names[ipproto_map][alproto].tx_name),
                            "%s%s%s", tx_str, alproto_str, ipproto_suffix);

                    if (ipproto == IPPROTO_TCP) {
                        snprintf(applayer_counter_names[ipproto_map][alproto].gap_error,
                                sizeof(applayer_counter_names[ipproto_map][alproto].gap_error),
                                "%s%s%s.gap", estr, alproto_str, ipproto_suffix);
                    }
                    snprintf(applayer_counter_names[ipproto_map][alproto].alloc_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].alloc_error),
                            "%s%s%s.alloc", estr, alproto_str, ipproto_suffix);
                    snprintf(applayer_counter_names[ipproto_map][alproto].parser_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].parser_error),
                            "%s%s%s.parser", estr, alproto_str, ipproto_suffix);
                    snprintf(applayer_counter_names[ipproto_map][alproto].internal_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].internal_error),
                            "%s%s%s.internal", estr, alproto_str, ipproto_suffix);
                } else {
                    snprintf(applayer_counter_names[ipproto_map][alproto].name,
                            sizeof(applayer_counter_names[ipproto_map][alproto].name),
                            "%s%s", str, alproto_str);
                    snprintf(applayer_counter_names[ipproto_map][alproto].tx_name,
                            sizeof(applayer_counter_names[ipproto_map][alproto].tx_name),
                            "%s%s", tx_str, alproto_str);

                    if (ipproto == IPPROTO_TCP) {
                        snprintf(applayer_counter_names[ipproto_map][alproto].gap_error,
                                sizeof(applayer_counter_names[ipproto_map][alproto].gap_error),
                                "%s%s.gap", estr, alproto_str);
                    }
                    snprintf(applayer_counter_names[ipproto_map][alproto].alloc_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].alloc_error),
                            "%s%s.alloc", estr, alproto_str);
                    snprintf(applayer_counter_names[ipproto_map][alproto].parser_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].parser_error),
                            "%s%s.parser", estr, alproto_str);
                    snprintf(applayer_counter_names[ipproto_map][alproto].internal_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].internal_error),
                            "%s%s.internal", estr, alproto_str);
                }
            } else if (alproto == ALPROTO_FAILED) {
                snprintf(applayer_counter_names[ipproto_map][alproto].name,
                        sizeof(applayer_counter_names[ipproto_map][alproto].name),
                        "%s%s%s", str, "failed", ipproto_suffix);
                if (ipproto == IPPROTO_TCP) {
                    snprintf(applayer_counter_names[ipproto_map][alproto].gap_error,
                            sizeof(applayer_counter_names[ipproto_map][alproto].gap_error),
                            "%sfailed%s.gap", estr, ipproto_suffix);
                }
            }
        }
    }
}

void AppLayerRegisterThreadCounters(ThreadVars *tv)
{
    const uint8_t ipprotos[] = { IPPROTO_TCP, IPPROTO_UDP };
    AppProto alprotos[ALPROTO_MAX];
    AppLayerProtoDetectSupportedAppProtocols(alprotos);

    for (uint8_t p = 0; p < IPPROTOS_MAX; p++) {
        const uint8_t ipproto = ipprotos[p];
        const uint8_t ipproto_map = FlowGetProtoMapping(ipproto);

        for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            if (alprotos[alproto] == 1) {
                applayer_counters[ipproto_map][alproto].counter_id =
                    StatsRegisterCounter(applayer_counter_names[ipproto_map][alproto].name, tv);

                applayer_counters[ipproto_map][alproto].counter_tx_id =
                    StatsRegisterCounter(applayer_counter_names[ipproto_map][alproto].tx_name, tv);

                if (ipproto == IPPROTO_TCP) {
                    applayer_counters[ipproto_map][alproto].gap_error_id = StatsRegisterCounter(
                            applayer_counter_names[ipproto_map][alproto].gap_error, tv);
                }
                applayer_counters[ipproto_map][alproto].alloc_error_id = StatsRegisterCounter(
                        applayer_counter_names[ipproto_map][alproto].alloc_error, tv);
                applayer_counters[ipproto_map][alproto].parser_error_id = StatsRegisterCounter(
                        applayer_counter_names[ipproto_map][alproto].parser_error, tv);
                applayer_counters[ipproto_map][alproto].internal_error_id = StatsRegisterCounter(
                        applayer_counter_names[ipproto_map][alproto].internal_error, tv);
            } else if (alproto == ALPROTO_FAILED) {
                applayer_counters[ipproto_map][alproto].counter_id =
                    StatsRegisterCounter(applayer_counter_names[ipproto_map][alproto].name, tv);

                if (ipproto == IPPROTO_TCP) {
                    applayer_counters[ipproto_map][alproto].gap_error_id = StatsRegisterCounter(
                            applayer_counter_names[ipproto_map][alproto].gap_error, tv);
                }
            }
        }
    }
}

void AppLayerDeSetupCounters()
{
    memset(applayer_counter_names, 0, sizeof(applayer_counter_names));
    memset(applayer_counters, 0, sizeof(applayer_counters));
}

/***** Unittests *****/

#ifdef UNITTESTS
#include "pkt-var.h"
#include "stream-tcp.h"
#include "stream-tcp-util.h"
#include "stream.h"
#include "util-unittest.h"

#define TEST_START                                                                                 \
    Packet *p = PacketGetFromAlloc();                                                              \
    FAIL_IF_NULL(p);                                                                               \
    Flow f;                                                                                        \
    ThreadVars tv;                                                                                 \
    StreamTcpThread *stt = NULL;                                                                   \
    TCPHdr tcph;                                                                                   \
    PacketQueueNoLock pq;                                                                          \
    memset(&pq, 0, sizeof(PacketQueueNoLock));                                                     \
    memset(p, 0, SIZE_OF_PACKET);                                                                  \
    memset(&f, 0, sizeof(Flow));                                                                   \
    memset(&tv, 0, sizeof(ThreadVars));                                                            \
    memset(&tcph, 0, sizeof(TCPHdr));                                                              \
                                                                                                   \
    FLOW_INITIALIZE(&f);                                                                           \
    f.flags = FLOW_IPV4;                                                                           \
    f.proto = IPPROTO_TCP;                                                                         \
    p->flow = &f;                                                                                  \
    p->tcph = &tcph;                                                                               \
                                                                                                   \
    StreamTcpInitConfig(true);                                                                     \
    IPPairInitConfig(true);                                                                        \
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);                                                 \
                                                                                                   \
    /* handshake */                                                                                \
    tcph.th_win = htons(5480);                                                                     \
    tcph.th_flags = TH_SYN;                                                                        \
    p->flowflags = FLOW_PKT_TOSERVER;                                                              \
    p->payload_len = 0;                                                                            \
    p->payload = NULL;                                                                             \
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);                                              \
    TcpSession *ssn = (TcpSession *)f.protoctx;                                                    \
                                                                                                   \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));                     \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));                     \
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);                                                         \
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(ssn->flags &STREAMTCP_FLAG_APP_LAYER_DISABLED);                                        \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(ssn->data_first_seen_dir != 0);                                                        \
                                                                                                   \
    /* handshake */                                                                                \
    p->tcph->th_ack = htonl(1);                                                                    \
    p->tcph->th_flags = TH_SYN | TH_ACK;                                                           \
    p->flowflags = FLOW_PKT_TOCLIENT;                                                              \
    p->payload_len = 0;                                                                            \
    p->payload = NULL;                                                                             \
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);                                              \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));                     \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));                     \
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);                                                         \
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(ssn->flags &STREAMTCP_FLAG_APP_LAYER_DISABLED);                                        \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(ssn->data_first_seen_dir != 0);                                                        \
                                                                                                   \
    /* handshake */                                                                                \
    p->tcph->th_ack = htonl(1);                                                                    \
    p->tcph->th_seq = htonl(1);                                                                    \
    p->tcph->th_flags = TH_ACK;                                                                    \
    p->flowflags = FLOW_PKT_TOSERVER;                                                              \
    p->payload_len = 0;                                                                            \
    p->payload = NULL;                                                                             \
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);                                              \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));                     \
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));                     \
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);                                                         \
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);                                                      \
    FAIL_IF(ssn->flags &STREAMTCP_FLAG_APP_LAYER_DISABLED);                                        \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));                                                 \
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));                                                 \
    FAIL_IF(ssn->data_first_seen_dir != 0);
#define TEST_END                                                                                   \
    StreamTcpSessionClear(p->flow->protoctx);                                                      \
    StreamTcpThreadDeinit(&tv, (void *)stt);                                                       \
    StreamTcpFreeConfig(true);                                                                     \
    PacketFree(p);                                                                                 \
    FLOW_DESTROY(&f);                                                                              \
    StatsThreadCleanup(&tv);

/**
 * \test GET -> HTTP/1.1
 */
static int AppLayerTest01(void)
{
    TEST_START;

    /* full request */
    uint8_t request[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test GE -> T -> HTTP/1.1
 */
static int AppLayerTest02(void)
{
    TEST_START;

    /* partial request */
    uint8_t request1[] = { 0x47, 0x45, };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack against partial request */
    p->tcph->th_ack = htonl(3);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* complete partial request */
    uint8_t request2[] = {
        0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(3);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request2);
    p->payload = request2;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test GET -> RUBBISH(PM AND PP DONE IN ONE GO)
 */
static int AppLayerTest03(void)
{
    TEST_START;

    /* request */
    uint8_t request[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* rubbish response */
    uint8_t response[] = {
        0x58, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_FAILED);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test GE -> RUBBISH(TC - PM AND PP NOT DONE) -> RUBBISH(TC - PM AND PP DONE).
 */
static int AppLayerTest04(void)
{
    TEST_START;

    /* request */
    uint8_t request[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    PrintRawDataFp(stdout, request, sizeof(request));
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);   // TOSERVER data now seen

    /* partial response */
    uint8_t response1[] = { 0x58, 0x54, 0x54, 0x50, };
    PrintRawDataFp(stdout, response1, sizeof(response1));
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response1);
    p->payload = response1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client)); // toserver complete
    FAIL_IF(f.alproto != ALPROTO_HTTP1);                                        // http based on ts
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);                                     // ts complete
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);  // first data sent to applayer

    /* partial response ack */
    p->tcph->th_ack = htonl(5);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client)); // toserver complete
    FAIL_IF(f.alproto != ALPROTO_HTTP1);                                        // http based on ts
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);                                     // ts complete
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));         // to client pp got nothing
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);  // first data sent to applayer

    /* remaining response */
    uint8_t response2[] = {
        0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    PrintRawDataFp(stdout, response2, sizeof(response2));
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response2);
    p->payload = response2;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client)); // toserver complete
    FAIL_IF(f.alproto != ALPROTO_HTTP1);                                        // http based on ts
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);                                     // ts complete
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));         // to client pp got nothing
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);  // first data sent to applayer

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server)); // toclient complete (failed)
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client)); // toserver complete
    FAIL_IF(f.alproto != ALPROTO_HTTP1);                                        // http based on ts
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);                                     // ts complete
    FAIL_IF(f.alproto_tc != ALPROTO_FAILED);                // tc failed
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));         // to client pp got nothing
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);  // first data sent to applayer

    TEST_END;
    PASS;
}

/**
 * \test RUBBISH -> HTTP/1.1
 */
static int AppLayerTest05(void)
{
    TEST_START;

    /* full request */
    uint8_t request[] = {
        0x48, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    PrintRawDataFp(stdout, request, sizeof(request));
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    PrintRawDataFp(stdout, response, sizeof(response));
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_FAILED);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test HTTP/1.1 -> GET
 */
static int AppLayerTest06(void)
{
    TEST_START;

    /* full response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOCLIENT);

    /* full request - response ack*/
    uint8_t request[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    p->tcph->th_ack = htonl(1 + sizeof(request));
    p->tcph->th_seq = htonl(328);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test GET -> DCERPC
 */
static int AppLayerTest07(void)
{
    TEST_START;

    /* full request */
    uint8_t request[] = {
        0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d, 0x6c, 0x20,
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30,
        0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20,
        0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
        0x74, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d,
        0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41,
        0x70, 0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e,
        0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20,
        0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = { 0x05, 0x00, 0x4d, 0x42, 0x00, 0x01, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30,
        0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46, 0x72, 0x69, 0x2c,
        0x20, 0x32, 0x33, 0x20, 0x53, 0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20, 0x30, 0x36,
        0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, 0x72,
        0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69, 0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f,
        0x32, 0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,
        0x64, 0x3a, 0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34, 0x20, 0x4e, 0x6f, 0x76, 0x20,
        0x32, 0x30, 0x31, 0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a, 0x34, 0x36, 0x20, 0x47,
        0x4d, 0x54, 0x0d, 0x0a, 0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61, 0x62, 0x38, 0x39,
        0x36, 0x35, 0x2d, 0x32, 0x63, 0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61, 0x37, 0x66,
        0x37, 0x66, 0x38, 0x30, 0x22, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x52,
        0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20,
        0x34, 0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a,
        0x20, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
        0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d,
        0x6c, 0x0d, 0x0a, 0x58, 0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76, 0x6f, 0x69, 0x64,
        0x20, 0x62, 0x72, 0x6f, 0x77, 0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d, 0x0a, 0x0d,
        0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c, 0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c, 0x68,
        0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_ts != ALPROTO_HTTP1);
    FAIL_IF(f.alproto_tc != ALPROTO_DCERPC);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test SMB -> HTTP/1.1
 */
static int AppLayerTest08(void)
{
    TEST_START;

    /* full request */
    uint8_t request[] = { 0x05, 0x00, 0x54, 0x20, 0x00, 0x01, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68,
        0x74, 0x6d, 0x6c, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x48,
        0x6f, 0x73, 0x74, 0x3a, 0x20, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x0d,
        0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x42, 0x65, 0x6e, 0x63, 0x68, 0x2f, 0x32, 0x2e, 0x33, 0x0d, 0x0a,
        0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = {
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_DCERPC);
    FAIL_IF(f.alproto_ts != ALPROTO_DCERPC);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_DCERPC);
    FAIL_IF(f.alproto_ts != ALPROTO_DCERPC);
    FAIL_IF(f.alproto_tc != ALPROTO_HTTP1);
    FAIL_IF(!(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test RUBBISH(TC - PM and PP NOT DONE) ->
 *       RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest09(void)
{
    TEST_START;

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64 };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response - request ack */
    p->tcph->th_ack = htonl(9);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full request */
    uint8_t request2[] = {
        0x44, 0x44, 0x45, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0xff };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(9);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request2);
    p->payload = request2;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = {
        0x55, 0x74, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(18);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_FAILED);
    FAIL_IF(f.alproto_ts != ALPROTO_FAILED);
    FAIL_IF(f.alproto_tc != ALPROTO_FAILED);
    FAIL_IF(!(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest10(void)
{
    TEST_START;

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0xff };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response - request ack */
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response[] = {
        0x55, 0x74, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(18);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_FAILED);
    FAIL_IF(f.alproto_ts != ALPROTO_FAILED);
    FAIL_IF(f.alproto_tc != ALPROTO_FAILED);
    FAIL_IF(!(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

/**
 * \test RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP NOT DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest11(void)
{
    TEST_START;

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64, 0xff };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response - request ack */
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* full response - request ack */
    uint8_t response1[] = {
        0x55, 0x74, 0x54, 0x50, };
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response1);
    p->payload = response1;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack from request */
    p->tcph->th_ack = htonl(5);
    p->tcph->th_seq = htonl(18);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    uint8_t response2[] = {
        0x2f, 0x31, 0x2e, 0x31,
        0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d,
        0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46,
        0x72, 0x69, 0x2c, 0x20, 0x32, 0x33, 0x20, 0x53,
        0x65, 0x70, 0x20, 0x32, 0x30, 0x31, 0x31, 0x20,
        0x30, 0x36, 0x3a, 0x32, 0x39, 0x3a, 0x33, 0x39,
        0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x41, 0x70,
        0x61, 0x63, 0x68, 0x65, 0x2f, 0x32, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x20, 0x28, 0x55, 0x6e, 0x69,
        0x78, 0x29, 0x20, 0x44, 0x41, 0x56, 0x2f, 0x32,
        0x0d, 0x0a, 0x4c, 0x61, 0x73, 0x74, 0x2d, 0x4d,
        0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x3a,
        0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x30, 0x34,
        0x20, 0x4e, 0x6f, 0x76, 0x20, 0x32, 0x30, 0x31,
        0x30, 0x20, 0x31, 0x35, 0x3a, 0x30, 0x34, 0x3a,
        0x34, 0x36, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a,
        0x45, 0x54, 0x61, 0x67, 0x3a, 0x20, 0x22, 0x61,
        0x62, 0x38, 0x39, 0x36, 0x35, 0x2d, 0x32, 0x63,
        0x2d, 0x34, 0x39, 0x34, 0x33, 0x62, 0x37, 0x61,
        0x37, 0x66, 0x37, 0x66, 0x38, 0x30, 0x22, 0x0d,
        0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d,
        0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20,
        0x62, 0x79, 0x74, 0x65, 0x73, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c,
        0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x20, 0x34,
        0x34, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
        0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63,
        0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x43, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79,
        0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74,
        0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x0d, 0x0a, 0x58,
        0x2d, 0x50, 0x61, 0x64, 0x3a, 0x20, 0x61, 0x76,
        0x6f, 0x69, 0x64, 0x20, 0x62, 0x72, 0x6f, 0x77,
        0x73, 0x65, 0x72, 0x20, 0x62, 0x75, 0x67, 0x0d,
        0x0a, 0x0d, 0x0a, 0x3c, 0x68, 0x74, 0x6d, 0x6c,
        0x3e, 0x3c, 0x62, 0x6f, 0x64, 0x79, 0x3e, 0x3c,
        0x68, 0x31, 0x3e, 0x49, 0x74, 0x20, 0x77, 0x6f,
        0x72, 0x6b, 0x73, 0x21, 0x3c, 0x2f, 0x68, 0x31,
        0x3e, 0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e,
        0x3c, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3e };
    p->tcph->th_ack = htonl(18);
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response2);
    p->payload = response2;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_ts != ALPROTO_UNKNOWN);
    FAIL_IF(f.alproto_tc != ALPROTO_UNKNOWN);
    FAIL_IF(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED);
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != STREAM_TOSERVER);

    /* response ack from request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(18);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    FAIL_IF(StreamTcpPacket(&tv, p, stt, &pq) == -1);
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server));
    FAIL_IF(!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client));
    FAIL_IF(f.alproto != ALPROTO_FAILED);
    FAIL_IF(f.alproto_ts != ALPROTO_FAILED);
    FAIL_IF(f.alproto_tc != ALPROTO_FAILED);
    FAIL_IF(!(ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOSERVER));
    FAIL_IF(!FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(!FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT));
    FAIL_IF(ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER);

    TEST_END;
    PASS;
}

void AppLayerUnittestsRegister(void)
{
    SCEnter();

    UtRegisterTest("AppLayerTest01", AppLayerTest01);
    UtRegisterTest("AppLayerTest02", AppLayerTest02);
    UtRegisterTest("AppLayerTest03", AppLayerTest03);
    UtRegisterTest("AppLayerTest04", AppLayerTest04);
    UtRegisterTest("AppLayerTest05", AppLayerTest05);
    UtRegisterTest("AppLayerTest06", AppLayerTest06);
    UtRegisterTest("AppLayerTest07", AppLayerTest07);
    UtRegisterTest("AppLayerTest08", AppLayerTest08);
    UtRegisterTest("AppLayerTest09", AppLayerTest09);
    UtRegisterTest("AppLayerTest10", AppLayerTest10);
    UtRegisterTest("AppLayerTest11", AppLayerTest11);

    SCReturn;
}

#endif /* UNITTESTS */
