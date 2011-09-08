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
 * Generic App-layer functions
 */

#include "suricata-common.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp-private.h"
#include "flow.h"

#include "util-debug.h"
#include "util-print.h"
#include "util-profiling.h"

//#define PRINT
extern uint8_t engine_mode;

/** \brief Get the active app layer proto from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval proto (ALPROTO_UNKNOWN if no proto yet) */
uint16_t AppLayerGetProtoFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    if (p->flow->aldata == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

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

    if (p->flow->aldata == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("p->flow->alproto %"PRIu16"", p->flow->alproto);

    void *alstate = p->flow->aldata[AlpGetStateIdx(p->flow->alproto)];

    SCLogDebug("p->flow %p", p->flow);
    SCReturnPtr(alstate, "void");
}

/** \brief Get the active app layer state from the flow
 *  \param f flow pointer to a LOCKED flow
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    SCEnter();

    if (f == NULL) {
        SCReturnPtr(NULL, "void");
    }

    if (f->aldata == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("f->alproto %"PRIu16"", f->alproto);

    void *alstate = f->aldata[AlpGetStateIdx(f->alproto)];
    SCReturnPtr(alstate, "void");
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
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleTCPData(AlpProtoDetectThreadCtx *dp_ctx, Flow *f,
        TcpSession *ssn, uint8_t *data, uint32_t data_len, uint8_t flags)
{
    SCEnter();

    uint16_t alproto = ALPROTO_UNKNOWN;
    int r = 0;

    BUG_ON(f == NULL);
    BUG_ON(ssn == NULL);

    alproto = f->alproto;

    SCLogDebug("data_len %u flags %02X", data_len, flags);
    if (!(f->flags & FLOW_NO_APPLAYER_INSPECTION)) {
        /* if we don't know the proto yet and we have received a stream
         * initializer message, we run proto detection.
         * We receive 2 stream init msgs (one for each direction) but we
         * only run the proto detection once. */
        if (alproto == ALPROTO_UNKNOWN && flags & STREAM_GAP) {
            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
            SCLogDebug("ALPROTO_UNKNOWN flow %p, due to GAP in stream start", f);
            StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
        } else if (alproto == ALPROTO_UNKNOWN && flags & STREAM_START) {
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
            alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f,
                    data, data_len, flags, IPPROTO_TCP);
            PACKET_PROFILING_APP_PD_END(dp_ctx);

            if (alproto != ALPROTO_UNKNOWN) {
                /* store the proto and setup the L7 data array */
                FlowL7DataPtrInit(f);
                f->alproto = alproto;
                ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

                PACKET_PROFILING_APP_START(dp_ctx, alproto);
                r = AppLayerParse(f, alproto, flags, data, data_len);
                PACKET_PROFILING_APP_END(dp_ctx, alproto);
            } else {
                if (flags & STREAM_TOSERVER) {
                    SCLogDebug("alp_proto_ctx.toserver.max_len %u", alp_proto_ctx.toserver.max_len);
                    if (f->flags & FLOW_TS_PM_PP_ALPROTO_DETECT_DONE) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
                        StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
                    }
                } else {
                    if (f->flags & FLOW_TC_PM_PP_ALPROTO_DETECT_DONE) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
                        StreamTcpSetSessionNoReassemblyFlag(ssn, 1);
                    }
                }
            }
        } else {
            SCLogDebug("stream data (len %" PRIu32 " alproto "
                    "%"PRIu16" (flow %p)", data_len, alproto, f);
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
            if (alproto != ALPROTO_UNKNOWN) {
                PACKET_PROFILING_APP_START(dp_ctx, alproto);
                r = AppLayerParse(f, alproto, flags, data, data_len);
                PACKET_PROFILING_APP_END(dp_ctx, alproto);
            } else {
                SCLogDebug(" smsg not start, but no l7 data? Weird");
            }
        }
    } else {
        SCLogDebug("FLOW_AL_NO_APPLAYER_INSPECTION is set");
    }

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
int AppLayerHandleTCPMsg(AlpProtoDetectThreadCtx *dp_ctx, StreamMsg *smsg)
{
    SCEnter();

#ifdef PRINT
    printf("=> Stream Data (raw reassembly) -- start %s%s\n",
            smsg->flags & STREAM_TOCLIENT ? "toclient" : "",
            smsg->flags & STREAM_TOSERVER ? "toserver" : "");
    PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
    printf("=> Stream Data -- end\n");
#endif
    SCLogDebug("smsg %p", smsg);
    BUG_ON(smsg->flow == NULL);

    TcpSession *ssn = smsg->flow->protoctx;
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

        /* flow is free again */
        FlowDecrUsecnt(smsg->flow);
        /* dereference the flow */
        smsg->flow = NULL;
    } else { /* no ssn ptr */
        /* if there is no ssn ptr we won't
         * be inspecting this msg in detect
         * so return it to the pool. */

        /* flow is free again */
        FlowDecrUsecnt(smsg->flow);

        /* return the used message to the queue */
        StreamMsgReturnToPool(smsg);
    }

    SCReturnInt(0);
}

#if 0
/**
 *  \brief Handle a app layer TCP message
 *
 *  If the protocol is yet unknown, the proto detection code is run first.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param smsg Stream message
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleMsg(AlpProtoDetectThreadCtx *dp_ctx, StreamMsg *smsg)
{
    SCEnter();

    uint16_t alproto = ALPROTO_UNKNOWN;
    int r = 0;

    SCLogDebug("smsg %p", smsg);

    BUG_ON(smsg->flow == NULL);

    TcpSession *ssn = smsg->flow->protoctx;
    if (ssn != NULL) {
        alproto = smsg->flow->alproto;

        if (!(smsg->flow->flags & FLOW_NO_APPLAYER_INSPECTION)) {
            /* if we don't know the proto yet and we have received a stream
             * initializer message, we run proto detection.
             * We receive 2 stream init msgs (one for each direction) but we
             * only run the proto detection once. */
            if (alproto == ALPROTO_UNKNOWN && smsg->flags & STREAM_START) {
                SCLogDebug("Stream initializer (len %" PRIu32 " (%" PRIu32 "))",
                        smsg->data.data_len, MSG_DATA_SIZE);

                //printf("=> Init Stream Data -- start\n");
                //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
                //printf("=> Init Stream Data -- end\n");

                alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f
                        smsg->data.data, smsg->data.data_len, smsg->flow->alflags, IPPROTO_TCP);
                if (alproto != ALPROTO_UNKNOWN) {
                    /* store the proto and setup the L7 data array */
                    FlowL7DataPtrInit(smsg->flow);
                    smsg->flow->alproto = alproto;
                    ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

                    r = AppLayerParse(smsg->flow, alproto, smsg->flow->alflags,
                            smsg->data.data, smsg->data.data_len);
                } else {
                    if (smsg->flags & STREAM_TOSERVER) {
                        if (smsg->data.data_len >= alp_proto_ctx.toserver.max_len) {
                            /* protocol detection has failed */
                            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                            smsg->flow->alflags |= FLOW_AL_NO_APPLAYER_INSPECTION;
                            SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                        }
                    } else if (smsg->flags & STREAM_TOCLIENT) {
                        if (smsg->data.data_len >= alp_proto_ctx.toclient.max_len) {
                            /* protocol detection has failed */
                            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                            smsg->flow->alflags |= FLOW_AL_NO_APPLAYER_INSPECTION;
                            SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                        }
                    }
                }
            } else {
                SCLogDebug("stream data (len %" PRIu32 " (%" PRIu32 ")), alproto "
                        "%"PRIu16" (flow %p)", smsg->data.data_len, MSG_DATA_SIZE,
                        alproto, smsg->flow);

                //printf("=> Stream Data -- start\n");
                //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
                //printf("=> Stream Data -- end\n");

                /* if we don't have a data object here we are not getting it
                 * a start msg should have gotten us one */
                if (alproto != ALPROTO_UNKNOWN) {
                    r = AppLayerParse(smsg->flow, alproto, smsg->flags,
                            smsg->data.data, smsg->data.data_len);
                } else {
                    SCLogDebug(" smsg not start, but no l7 data? Weird");
                }
            }
        }

        SCLogDebug("storing smsg %p in the tcp session", smsg);

        /* store the smsg in the tcp stream */
        if (smsg->flags & STREAM_TOSERVER) {
            SCLogDebug("storing smsg in the to_server");
#if 0
            PrintRawDataFp(stdout,smsg->data.data,smsg->data.data_len);
#endif
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

        /* flow is free again */
        FlowDecrUsecnt(smsg->flow);
        /* dereference the flow */
        smsg->flow = NULL;

    } else { /* no ssn ptr */

        /* if there is no ssn ptr we won't
         * be inspecting this msg in detect
         * so return it to the pool. */

        /* flow is free again */
        FlowDecrUsecnt(smsg->flow);

        /* return the used message to the queue */
        StreamMsgReturnToPool(smsg);
    }

    SCReturnInt(r);
}
#endif

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

    uint16_t alproto = ALPROTO_UNKNOWN;
    int r = 0;

    if (f == NULL) {
        SCReturnInt(r);
    }

    SCMutexLock(&f->m);

    alproto = f->alproto;

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
    if (alproto == ALPROTO_UNKNOWN && !(f->flags & FLOW_ALPROTO_DETECT_DONE)) {
        SCLogDebug("Detecting AL proto on udp mesg (len %" PRIu32 ")",
                    p->payload_len);

        //printf("=> Init Stream Data -- start\n");
        //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
        //printf("=> Init Stream Data -- end\n");

        alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx, f,
                        p->payload, p->payload_len, flags, IPPROTO_UDP);
        if (alproto != ALPROTO_UNKNOWN) {
            /* store the proto and setup the L7 data array */
            FlowL7DataPtrInit(f);
            f->alproto = alproto;
            f->flags |= FLOW_ALPROTO_DETECT_DONE;

            r = AppLayerParse(f, alproto, flags,
                           p->payload, p->payload_len);
        } else {
            f->flags |= FLOW_ALPROTO_DETECT_DONE;
            SCLogDebug("ALPROTO_UNKNOWN flow %p", f);
        }
    } else {
        SCLogDebug("stream data (len %" PRIu32 " ), alproto "
                  "%"PRIu16" (flow %p)", p->payload_len, alproto, f);

        //printf("=> Stream Data -- start\n");
        //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
        //printf("=> Stream Data -- end\n");

        /* if we don't have a data object here we are not getting it
         * a start msg should have gotten us one */
        if (alproto != ALPROTO_UNKNOWN) {
            r = AppLayerParse(f, alproto, flags,
                        p->payload, p->payload_len);
        } else {
            SCLogDebug(" udp session not start, but no l7 data? Weird");
        }
    }

    SCMutexUnlock(&f->m);
    SCReturnInt(r);
}

