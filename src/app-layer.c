/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * Generic App-layer functions
 */

#include "suricata-common.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "stream-tcp-inline.h"
#include "flow.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "decode-events.h"

//#define PRINT
extern uint8_t engine_mode;

/** \brief Get the active app layer proto from the packet
 *  \param p packet pointer with a LOCKED flow
 *  \retval alstate void pointer to the state
 *  \retval proto (ALPROTO_UNKNOWN if no proto yet) */
uint16_t AppLayerGetProtoFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    SCLogDebug("p->flow->alproto %"PRIu16"", p->flow->alproto);

    SCReturnUInt(p->flow->alproto);
}

/** \brief Get the active app layer state from the packet
 *  \param p packet pointer with a LOCKED flow
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnPtr(NULL, "void");
    }

    DEBUG_ASSERT_FLOW_LOCKED(p->flow);

    SCLogDebug("p->flow->alproto %"PRIu16"", p->flow->alproto);

    SCLogDebug("p->flow %p", p->flow);
    SCReturnPtr(p->flow->alstate, "void");
}

/** \brief Get the active app layer state from the flow
 *  \param f flow pointer to a LOCKED flow
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (f == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("f->alproto %"PRIu16"", f->alproto);

    SCReturnPtr(f->alstate, "void");
}

/** global app layer detection context */
extern AlpProtoDetectCtx alp_proto_ctx;

/**
 *  \brief Handle a chunk of TCP data
 *
 *  If the protocol is yet unknown, the proto detection code is run first.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param f Flow
 *  \param ssn TCP Session
 *  \param data ptr to reassembled data
 *  \param data_len length of the data chunk
 *  \param flags control flags
 *
 *  During detection this function can call the stream reassembly,
 *  inline or non-inline for the opposing direction, while already
 *  being called by the same stream reassembly for a particular
 *  direction.  This should cause any issues, since processing of
 *  each stream is independent of the other stream.
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                          Flow *f, TcpSession *ssn, TcpStream *stream,
                          uint8_t *data, uint32_t data_len, Packet *p,
                          uint8_t flags)
{
    SCEnter();
    AlpProtoDetectThreadCtx *dp_ctx = &ra_ctx->dp_ctx;

    DEBUG_ASSERT_FLOW_LOCKED(f);

    int r = 0;

#if DEBUG
    BUG_ON(f == NULL);
    BUG_ON(ssn == NULL);
#endif

    SCLogDebug("data_len %u flags %02X", data_len, flags);
    if (f->flags & FLOW_NO_APPLAYER_INSPECTION) {
        SCLogDebug("FLOW_AL_NO_APPLAYER_INSPECTION is set");
        SCReturnInt(r);
    }

    uint16_t *alproto;
    uint16_t *alproto_otherdir;
    uint8_t dir;
    if (flags & STREAM_TOSERVER) {
        alproto = &f->alproto_ts;
        alproto_otherdir = &f->alproto_tc;
        dir = 0;
    } else {
        alproto = &f->alproto_tc;
        alproto_otherdir = &f->alproto_ts;
        dir = 1;
    }
    SCLogDebug("dir %u alproto %u alproto_other_dir %u",
            dir, *alproto, *alproto_otherdir);
    //PrintRawDataFp(stdout, data, data_len);

    /* if we don't know the proto yet and we have received a stream
     * initializer message, we run proto detection.
     * We receive 2 stream init msgs (one for each direction) but we
     * only run the proto detection once. */
    if (*alproto == ALPROTO_UNKNOWN && (flags & STREAM_GAP)) {
        StreamTcpSetStreamFlagAppProtoDetectionCompleted(stream);
        SCLogDebug("ALPROTO_UNKNOWN flow %p, due to GAP in stream start", f);
        StreamTcpSetSessionNoReassemblyFlag(ssn, dir);
    } else if (*alproto == ALPROTO_UNKNOWN && (flags & STREAM_START)) {
        uint32_t data_al_so_far;
        if (data_len == 0)
            data_al_so_far = 0;
        else
            data_al_so_far = f->data_al_so_far[dir];

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

        PACKET_PROFILING_APP_PD_START(dp_ctx);
        *alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f,
                                          data, data_len, flags, IPPROTO_TCP);
        PACKET_PROFILING_APP_PD_END(dp_ctx);
        SCLogDebug("alproto %u", *alproto);

        if (*alproto != ALPROTO_UNKNOWN) {
            if (*alproto_otherdir != ALPROTO_UNKNOWN && *alproto_otherdir != *alproto) {
                AppLayerDecoderEventsSetEventRaw(p->app_layer_events,
                                                 APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS);
                /* it indicates some data has already been sent to the parser */
                if (ssn->data_first_seen_dir == APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
                    f->alproto = *alproto = *alproto_otherdir;
                } else {
                    if (flags & STREAM_TOCLIENT)
                        f->alproto = *alproto_otherdir = *alproto;
                    else
                        f->alproto = *alproto = *alproto_otherdir;
                }
            }

            f->alproto = *alproto;
            SCLogDebug("calling StreamTcpSetStreamFlagAppProtoDetectionCompleted "
                    "on stream %p (%s)", stream, (stream == &ssn->client) ?
                    "ssn->client" : "ssn->server");
            StreamTcpSetStreamFlagAppProtoDetectionCompleted(stream);

            /* if we have seen data from the other direction first, send
             * data for that direction first to the parser.  This shouldn't
             * be an issue, since each stream processing happens
             * independently of the other stream direction.  At this point of
             * call, you need to know that this function's already being
             * called by the very same StreamReassembly() function that we
             * will now call shortly for the opposing direction. */
            if ((ssn->data_first_seen_dir & (STREAM_TOSERVER | STREAM_TOCLIENT)) &&
                !(flags & ssn->data_first_seen_dir)) {
                SCLogDebug("entering opposing dir hack");
                TcpStream *opposing_stream = NULL;
                if (stream == &ssn->client) {
                    opposing_stream = &ssn->server;
                    if (StreamTcpInlineMode()) {
                        p->flowflags &= ~FLOW_PKT_TOSERVER;
                        p->flowflags |= FLOW_PKT_TOCLIENT;
                    } else {
                        p->flowflags &= ~FLOW_PKT_TOCLIENT;
                        p->flowflags |= FLOW_PKT_TOSERVER;
                    }
                } else {
                    opposing_stream = &ssn->client;
                    if (StreamTcpInlineMode()) {
                        p->flowflags &= ~FLOW_PKT_TOCLIENT;
                        p->flowflags |= FLOW_PKT_TOSERVER;
                    } else {
                        p->flowflags &= ~FLOW_PKT_TOSERVER;
                        p->flowflags |= FLOW_PKT_TOCLIENT;
                    }
                }
                int ret;
                if (StreamTcpInlineMode()) {
                    ret = StreamTcpReassembleInlineAppLayer(tv, ra_ctx, ssn,
                                                            opposing_stream, p);
                } else {
                    ret = StreamTcpReassembleAppLayer(tv, ra_ctx, ssn,
                                                      opposing_stream, p);
                }
                if (stream == &ssn->client) {
                    if (StreamTcpInlineMode()) {
                        p->flowflags &= ~FLOW_PKT_TOCLIENT;
                        p->flowflags |= FLOW_PKT_TOSERVER;
                    } else {
                        p->flowflags &= ~FLOW_PKT_TOSERVER;
                        p->flowflags |= FLOW_PKT_TOCLIENT;
                    }
                } else {
                    if (StreamTcpInlineMode()) {
                        p->flowflags &= ~FLOW_PKT_TOSERVER;
                        p->flowflags |= FLOW_PKT_TOCLIENT;
                    } else {
                        p->flowflags &= ~FLOW_PKT_TOCLIENT;
                        p->flowflags |= FLOW_PKT_TOSERVER;
                    }
                }
                SCLogDebug("ret %d", ret);
                if (ret < 0) {
                    FlowSetSessionNoApplayerInspectionFlag(f);
                    SCLogDebug("calling StreamTcpSetStreamFlagAppProtoDetectionCompleted "
                            "on both streams");
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
                    r = -1;
                    goto end;
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
                if (al_proto_table[*alproto].first_data_dir &&
                    !(al_proto_table[*alproto].first_data_dir & ssn->data_first_seen_dir))
                {
                    AppLayerDecoderEventsSetEventRaw(p->app_layer_events,
                                                     APPLAYER_WRONG_DIRECTION_FIRST_DATA);
                    FlowSetSessionNoApplayerInspectionFlag(f);
                    SCLogDebug("calling StreamTcpSetStreamFlagAppProtoDetectionCompleted "
                            "on both streams");
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
                    /* Set a value that is neither STREAM_TOSERVER, nor STREAM_TOCLIENT */
                    ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;
                    r = -1;
                    goto end;
                }
                /* This can happen if the current direction is not the
                 * right direction, and the data from the other(also
                 * the right direction) direction is available to be sent
                 * to the app layer, but it is not ack'ed yet and hence
                 * the forced call to STreamTcpAppLayerReassemble still
                 * hasn't managed to send data from the other direction
                 * to the app layer. */
                if (al_proto_table[*alproto].first_data_dir &&
                    !(al_proto_table[*alproto].first_data_dir & flags))
                {
                    BUG_ON(*alproto_otherdir != ALPROTO_UNKNOWN);
                    AppLayerParserCleanupState(f);
                    f->alproto = *alproto = ALPROTO_UNKNOWN;
                    StreamTcpResetStreamFlagAppProtoDetectionCompleted(stream);
                    FLOW_RESET_PM_DONE(f, flags);
                    FLOW_RESET_PP_DONE(f, flags);
                    r = 0;
                    goto end;
                }
            }

            /* Set a value that is neither STREAM_TOSERVER, nor STREAM_TOCLIENT */
            ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;

            PACKET_PROFILING_APP_START(dp_ctx, *alproto);
            r = AppLayerParse(dp_ctx->alproto_local_storage[*alproto], f, *alproto, flags, data + data_al_so_far, data_len - data_al_so_far);
            PACKET_PROFILING_APP_END(dp_ctx, *alproto);
            f->data_al_so_far[dir] = 0;
        } else {
            SCLogDebug("alproto == ALPROTO_UNKNOWN (%u)", *alproto);
            if (*alproto_otherdir != ALPROTO_UNKNOWN) {
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
                    (al_proto_table[*alproto_otherdir].first_data_dir) &&
                    !(al_proto_table[*alproto_otherdir].first_data_dir & flags))
                {
                    r = -1;
                    FlowSetSessionNoApplayerInspectionFlag(f);
                    SCLogDebug("calling StreamTcpSetStreamFlagAppProtoDetectionCompleted "
                            "on both streams");
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
                    goto end;
                }

                if (data_len > 0)
                    ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;

                PACKET_PROFILING_APP_START(dp_ctx, *alproto_otherdir);
                r = AppLayerParse(dp_ctx->alproto_local_storage[*alproto_otherdir], f, *alproto_otherdir, flags,
                                  data + data_al_so_far, data_len - data_al_so_far);
                PACKET_PROFILING_APP_END(dp_ctx, *alproto_otherdir);
                if (FLOW_IS_PM_DONE(f, flags) && FLOW_IS_PP_DONE(f, flags)) {
                    AppLayerDecoderEventsSetEventRaw(p->app_layer_events,
                                                     APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION);
                    SCLogDebug("calling StreamTcpSetStreamFlagAppProtoDetectionCompleted "
                            "on stream %p (%s)", stream, (stream == &ssn->client) ?
                            "ssn->client" : "ssn->server");
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(stream);
                    f->data_al_so_far[dir] = 0;
                } else {
                    f->data_al_so_far[dir] = data_len;
                    SCLogDebug("data_len %u stored in flow for dir %u", data_len, dir);
                }
            } else {

                SCLogDebug("both unknown FLOW_IS_PM_DONE(f, STREAM_TOSERVER) %s "
                                        "FLOW_IS_PP_DONE(f, STREAM_TOSERVER) %s "
                                        "FLOW_IS_PM_DONE(f, STREAM_TOCLIENT) %s "
                                        "FLOW_IS_PP_DONE(f, STREAM_TOCLIENT) %s,"
                                        " stream ts %u stream tc %u",
                        FLOW_IS_PM_DONE(f, STREAM_TOSERVER)?"true":"false",
                        FLOW_IS_PP_DONE(f, STREAM_TOSERVER)?"true":"false",
                        FLOW_IS_PM_DONE(f, STREAM_TOCLIENT)?"true":"false",
                        FLOW_IS_PP_DONE(f, STREAM_TOCLIENT)?"true":"false",
                        StreamTcpGetStreamSize(&ssn->client), StreamTcpGetStreamSize(&ssn->server));

                int flow_done = 0;
                if (FLOW_IS_PM_DONE(f, STREAM_TOSERVER) && FLOW_IS_PP_DONE(f, STREAM_TOSERVER) &&
                    FLOW_IS_PM_DONE(f, STREAM_TOCLIENT) && FLOW_IS_PP_DONE(f, STREAM_TOCLIENT)) {
                    SCLogDebug("proto detection failed for both streams");
                    flow_done = 1;
                } else if (FLOW_IS_PM_DONE(f, STREAM_TOSERVER) && FLOW_IS_PP_DONE(f, STREAM_TOSERVER) &&
                           StreamTcpGetStreamSize(&ssn->server) == 0 &&
                           StreamTcpGetStreamSize(&ssn->client) > alp_proto_ctx.toserver.async_max) {
                    SCLogDebug("%u bytes toserver and no proto, no data to "
                               "client, giving up", alp_proto_ctx.toserver.async_max);
                    ssn->server.flags |= STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED;
                    flow_done = 1;
                } else if (FLOW_IS_PM_DONE(f, STREAM_TOCLIENT) && FLOW_IS_PP_DONE(f, STREAM_TOCLIENT) &&
                           StreamTcpGetStreamSize(&ssn->client) == 0 &&
                           StreamTcpGetStreamSize(&ssn->server) > alp_proto_ctx.toclient.async_max) {
                    SCLogDebug("%u bytes toclient and no proto, no data to "
                               "server, giving up", alp_proto_ctx.toclient.async_max);
                    ssn->client.flags |= STREAMTCP_STREAM_FLAG_APPPROTO_DETECTION_SKIPPED;
                    flow_done = 1;
                }

                if (flow_done) {
                    FlowSetSessionNoApplayerInspectionFlag(f);
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->server);
                    StreamTcpSetStreamFlagAppProtoDetectionCompleted(&ssn->client);
                    ssn->data_first_seen_dir = APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER;
                }
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
            PACKET_PROFILING_APP_START(dp_ctx, f->alproto);
            r = AppLayerParse(dp_ctx->alproto_local_storage[f->alproto], f, f->alproto, flags, data, data_len);
            PACKET_PROFILING_APP_END(dp_ctx, f->alproto);
        } else {
            SCLogDebug(" smsg not start, but no l7 data? Weird");
        }
    }

 end:
    SCReturnInt(r);
}

/**
 *  \brief Attach a stream message to the TCP session for inspection
 *         in the detection engine.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param smsg Stream message
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleTCPMsg(AlpProtoDetectThreadCtx *dp_ctx, StreamMsg *smsg, TcpSession *ssn)
{
    SCEnter();

#ifdef PRINT
    printf("=> Stream Data (raw reassembly) -- start %s%s\n",
            smsg->flags & STREAM_TOCLIENT ? "toclient" : "",
            smsg->flags & STREAM_TOSERVER ? "toserver" : "");
    PrintRawDataFp(stdout, smsg->data, smsg->data_len);
    printf("=> Stream Data -- end\n");
#endif
    SCLogDebug("smsg %p", smsg);
    BUG_ON(smsg->flow == NULL);

    if (ssn != NULL) {
        SCLogDebug("storing smsg %p in the tcp session", smsg);

        /* store the smsg in the tcp stream */
        if (smsg->flags & STREAM_TOSERVER) {
            SCLogDebug("storing smsg in the to_server");

            /* put the smsg in the stream list */
            if (ssn->toserver_smsg_head == NULL) {
                ssn->toserver_smsg_head = smsg;
                ssn->toserver_smsg_tail = smsg;
                smsg->next = NULL;
                smsg->prev = NULL;
            } else {
                StreamMsg *cur = ssn->toserver_smsg_tail;
                cur->next = smsg;
                smsg->prev = cur;
                smsg->next = NULL;
                ssn->toserver_smsg_tail = smsg;
            }
        } else {
            SCLogDebug("storing smsg in the to_client");

            /* put the smsg in the stream list */
            if (ssn->toclient_smsg_head == NULL) {
                ssn->toclient_smsg_head = smsg;
                ssn->toclient_smsg_tail = smsg;
                smsg->next = NULL;
                smsg->prev = NULL;
            } else {
                StreamMsg *cur = ssn->toclient_smsg_tail;
                cur->next = smsg;
                smsg->prev = cur;
                smsg->next = NULL;
                ssn->toclient_smsg_tail = smsg;
            }
        }

        FlowDeReference(&smsg->flow);
    } else { /* no ssn ptr */
        /* if there is no ssn ptr we won't
         * be inspecting this msg in detect
         * so return it to the pool. */

        FlowDeReference(&smsg->flow);

        /* return the used message to the queue */
        StreamMsgReturnToPool(smsg);
    }

    SCReturnInt(0);
}

/**
 *  \brief Handle a app layer UDP message
 *
 *  If the protocol is yet unknown, the proto detection code is run first.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param f unlocked flow
 *  \param p UDP packet
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleUdp(AlpProtoDetectThreadCtx *dp_ctx, Flow *f, Packet *p)
{
    SCEnter();

    int r = 0;

    if (f == NULL) {
        SCReturnInt(r);
    }

    FLOWLOCK_WRLOCK(f);

    uint8_t flags = 0;
    if (p->flowflags & FLOW_PKT_TOSERVER) {
        flags |= STREAM_TOSERVER;
    } else {
        flags |= STREAM_TOCLIENT;
    }

    /* if we don't know the proto yet and we have received a stream
     * initializer message, we run proto detection.
     * We receive 2 stream init msgs (one for each direction) but we
     * only run the proto detection once. */
    if (f->alproto == ALPROTO_UNKNOWN && !(f->flags & FLOW_ALPROTO_DETECT_DONE)) {
        SCLogDebug("Detecting AL proto on udp mesg (len %" PRIu32 ")",
                    p->payload_len);

        PACKET_PROFILING_APP_PD_START(dp_ctx);
        f->alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f,
                        p->payload, p->payload_len, flags, IPPROTO_UDP);
        PACKET_PROFILING_APP_PD_END(dp_ctx);

        if (f->alproto != ALPROTO_UNKNOWN) {
            f->flags |= FLOW_ALPROTO_DETECT_DONE;

            PACKET_PROFILING_APP_START(dp_ctx, f->alproto);
            r = AppLayerParse(dp_ctx->alproto_local_storage[f->alproto], f, f->alproto, flags,
                              p->payload, p->payload_len);
            PACKET_PROFILING_APP_END(dp_ctx, f->alproto);
        } else {
            f->flags |= FLOW_ALPROTO_DETECT_DONE;
            SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
        }
    } else {
        SCLogDebug("stream data (len %" PRIu32 " ), alproto "
                  "%"PRIu16" (flow %p)", p->payload_len, f->alproto, f);

        /* if we don't have a data object here we are not getting it
         * a start msg should have gotten us one */
        if (f->alproto != ALPROTO_UNKNOWN) {
            PACKET_PROFILING_APP_START(dp_ctx, f->alproto);
            r = AppLayerParse(dp_ctx->alproto_local_storage[f->alproto], f, f->alproto, flags,
                              p->payload, p->payload_len);
            PACKET_PROFILING_APP_END(dp_ctx, f->alproto);
        } else {
            SCLogDebug("udp session has started, but failed to detect alproto "
                       "for l7");
        }
    }

    FLOWLOCK_UNLOCK(f);
    PACKET_PROFILING_APP_STORE(dp_ctx, p);
    SCReturnInt(r);
}

/************Unittests*************/

#ifdef UNITTESTS

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-util.h"
#include "stream.h"
#include "util-unittest.h"

/**
 * \test GET -> HTTP/1.1
 */
static int AppLayerTest01(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test GE -> T -> HTTP/1.1
 */
static int AppLayerTest02(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* handshake */
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* partial request */
    uint8_t request1[] = { 0x47, 0x45, };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* response ack against partial request */
    p->tcph->th_ack = htonl(3);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 6\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 7\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 8\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test GET -> RUBBISH(PM AND PP DONE IN ONE GO)
 */
 static int AppLayerTest03(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test GE -> RUBBISH(TC - PM AND PP NOT DONE) -> RUBBISH(TC - PM AND PP DONE).
 */
static int AppLayerTest04(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    /* handshake */
    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* partial response */
    uint8_t response1[] = { 0x58, 0x54, 0x54, 0x50, };
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response1);
    p->payload = response1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    /* partial response ack */
    p->tcph->th_ack = htonl(5);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 4 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

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
    p->tcph->th_ack = htonl(88);
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response2);
    p->payload = response2;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 4 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 7\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 8\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test RUBBISH -> HTTP/1.1
 */
static int AppLayerTest05(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request);
    p->payload = request;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test HTTP/1.1 -> GET
 */
static int AppLayerTest06(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOCLIENT) {
        printf("failure 4\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test GET -> DCERPC
 */
static int AppLayerTest07(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* full response - request ack */
    uint8_t response[] = {
        0x05, 0x00, 0x4d, 0x42, 0x2f, 0x31, 0x2e, 0x31,
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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_HTTP ||
        f.alproto_ts != ALPROTO_HTTP ||
        f.alproto_tc != ALPROTO_HTTP ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        (f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test SMB -> HTTP/1.1
 */
static int AppLayerTest08(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* full request */
    uint8_t request[] = {
        0x05, 0x00, 0x54, 0x20, 0x2f, 0x69, 0x6e, 0x64,
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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

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
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_DCERPC ||
        f.alproto_ts != ALPROTO_DCERPC ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 5\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(88);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_DCERPC ||
        f.alproto_ts != ALPROTO_DCERPC ||
        f.alproto_tc != ALPROTO_DCERPC ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 6\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test RUBBISH(TC - PM and PP NOT DONE) ->
 *       RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest09(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64 };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* response - request ack */
    p->tcph->th_ack = htonl(9);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

    /* full request */
    uint8_t request2[] = {
        0x44, 0x44, 0x45, 0x20, 0x2f, 0x69, 0x6e, 0x64 };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(9);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request2);
    p->payload = request2;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 6\n");
        goto end;
    }

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
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 7\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(17);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 8\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest10(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64 };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* response - request ack */
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

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
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response);
    p->payload = response;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 7\n");
        goto end;
    }

    /* response ack */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(17);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 8\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

/**
 * \test RUBBISH(TC - PM and PP DONE) ->
 *       RUBBISH(TS - PM and PP NOT DONE) ->
 *       RUBBISH(TS - PM and PP DONE)
 */
static int AppLayerTest11(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Flow f;
    ThreadVars tv;
    StreamTcpThread *stt = NULL;
    TCPHdr tcph;
    PacketQueue pq;
    memset(&pq,0,sizeof(PacketQueue));
    memset(p, 0, SIZE_OF_PACKET);
    memset (&f, 0, sizeof(Flow));
    memset(&tv, 0, sizeof (ThreadVars));
    StreamTcpThreadInit(&tv, NULL, (void **)&stt);
    memset(&tcph, 0, sizeof (TCPHdr));

    f.flags = FLOW_IPV4;
    p->flow = &f;
    p->tcph = &tcph;

    int ret = 0;

    StreamTcpInitConfig(TRUE);

    tcph.th_win = htons(5480);
    tcph.th_flags = TH_SYN;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;

    TcpSession *ssn = (TcpSession *)f.protoctx;

    /* handshake */
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 1\n");
        goto end;
    }


    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_flags = TH_SYN | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 2\n");
        goto end;
    }

    /* handshake */
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != 0) {
        printf("failure 3\n");
        goto end;
    }

    /* full request */
    uint8_t request1[] = {
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64,
        0x47, 0x47, 0x49, 0x20, 0x2f, 0x69, 0x6e, 0x64 };
    p->tcph->th_ack = htonl(1);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = sizeof(request1);
    p->payload = request1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 4\n");
        goto end;
    }

    /* response - request ack */
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 5\n");
        goto end;
    }

    /* full response - request ack */
    uint8_t response1[] = {
        0x55, 0x74, 0x54, 0x50, };
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(1);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response1);
    p->payload = response1;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 6\n");
        goto end;
    }

    /* response ack from request */
    p->tcph->th_ack = htonl(5);
    p->tcph->th_seq = htonl(17);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 7\n");
        goto end;
    }

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
    p->tcph->th_ack = htonl(17);
    p->tcph->th_seq = htonl(5);
    p->tcph->th_flags = TH_PUSH | TH_ACK;
    p->flowflags = FLOW_PKT_TOCLIENT;
    p->payload_len = sizeof(response2);
    p->payload = response2;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        f.flags & FLOW_NO_APPLAYER_INSPECTION ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != STREAM_TOSERVER) {
        printf("failure 8\n");
        goto end;
    }

    /* response ack from request */
    p->tcph->th_ack = htonl(328);
    p->tcph->th_seq = htonl(17);
    p->tcph->th_flags = TH_ACK;
    p->flowflags = FLOW_PKT_TOSERVER;
    p->payload_len = 0;
    p->payload = NULL;
    if (StreamTcpPacket(&tv, p, stt, &pq) == -1)
        goto end;
    if (!StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->server) ||
        !StreamTcpIsSetStreamFlagAppProtoDetectionCompleted(&ssn->client) ||
        f.alproto != ALPROTO_UNKNOWN ||
        f.alproto_ts != ALPROTO_UNKNOWN ||
        f.alproto_tc != ALPROTO_UNKNOWN ||
        f.data_al_so_far[0] != 0 ||
        f.data_al_so_far[1] != 0 ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOSERVER) || !FLOW_IS_PP_DONE(&f, STREAM_TOSERVER) ||
        !FLOW_IS_PM_DONE(&f, STREAM_TOCLIENT) || !FLOW_IS_PP_DONE(&f, STREAM_TOCLIENT) ||
        ssn->data_first_seen_dir != APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER) {
        printf("failure 9\n");
        goto end;
    }

    StreamTcpSessionClear(p->flow->protoctx);

    ret = 1;
end:
    StreamTcpFreeConfig(TRUE);
    SCFree(p);
    return ret;
}

#endif

void AppLayerRegisterUnittests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AppLayerTest01", AppLayerTest01, 1);
    UtRegisterTest("AppLayerTest02", AppLayerTest02, 1);
    UtRegisterTest("AppLayerTest03", AppLayerTest03, 1);
    UtRegisterTest("AppLayerTest04", AppLayerTest04, 1);
    UtRegisterTest("AppLayerTest05", AppLayerTest05, 1);
    UtRegisterTest("AppLayerTest06", AppLayerTest06, 1);
    UtRegisterTest("AppLayerTest07", AppLayerTest07, 1);
    UtRegisterTest("AppLayerTest08", AppLayerTest08, 1);
    UtRegisterTest("AppLayerTest09", AppLayerTest09, 1);
    UtRegisterTest("AppLayerTest10", AppLayerTest10, 1);
    UtRegisterTest("AppLayerTest11", AppLayerTest11, 1);
#endif

    return;
}
