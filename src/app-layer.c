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

        /* Copy some needed flags */
        if (smsg->flags & STREAM_TOSERVER)
            smsg->flow->alflags |= FLOW_AL_STREAM_TOSERVER;
        if (smsg->flags & STREAM_TOCLIENT)
            smsg->flow->alflags |= FLOW_AL_STREAM_TOCLIENT;
        if (smsg->flags & STREAM_GAP)
            smsg->flow->alflags |= FLOW_AL_STREAM_GAP;
        if (smsg->flags & STREAM_EOF)
            smsg->flow->alflags |= FLOW_AL_STREAM_EOF;

        if (!(smsg->flow->alflags & FLOW_AL_NO_APPLAYER_INSPECTION)) {
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

                alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx,
                        smsg->data.data, smsg->data.data_len, smsg->flow->alflags, IPPROTO_TCP);
                if (alproto != ALPROTO_UNKNOWN) {
                    /* store the proto and setup the L7 data array */
                    FlowL7DataPtrInit(smsg->flow);
                    smsg->flow->alproto = alproto;
                    ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                    smsg->flow->alflags |= FLOW_AL_PROTO_DETECT_DONE;

                    r = AppLayerParse(smsg->flow, alproto, smsg->flow->alflags,
                            smsg->data.data, smsg->data.data_len);
                } else {
                    if (smsg->flags & STREAM_TOSERVER) {
                        if (smsg->data.data_len >= alp_proto_ctx.toserver.max_len) {
                            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                            smsg->flow->alflags |= FLOW_AL_PROTO_DETECT_DONE;
                            SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                            StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
                        }
                    } else if (smsg->flags & STREAM_TOCLIENT) {
                        if (smsg->data.data_len >= alp_proto_ctx.toclient.max_len) {
                            ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                            smsg->flow->alflags |= FLOW_AL_PROTO_DETECT_DONE;
                            SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                            StreamTcpSetSessionNoReassemblyFlag(ssn, 1);
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

    if (p->flowflags & FLOW_PKT_TOSERVER) {
        f->alflags |= FLOW_AL_STREAM_TOSERVER;
    } else {
        f->alflags |= FLOW_AL_STREAM_TOCLIENT;
    }

    /* if we don't know the proto yet and we have received a stream
     * initializer message, we run proto detection.
     * We receive 2 stream init msgs (one for each direction) but we
     * only run the proto detection once. */
    if (alproto == ALPROTO_UNKNOWN && !(f->alflags & FLOW_AL_PROTO_DETECT_DONE)) {
        SCLogDebug("Detecting AL proto on udp mesg (len %" PRIu32 ")",
                    p->payload_len);

        //printf("=> Init Stream Data -- start\n");
        //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
        //printf("=> Init Stream Data -- end\n");

        alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx,
                        p->payload, p->payload_len, f->alflags, IPPROTO_UDP);
        if (alproto != ALPROTO_UNKNOWN) {
            /* store the proto and setup the L7 data array */
            FlowL7DataPtrInit(f);
            f->alproto = alproto;
            f->alflags &= ~FLOW_AL_PROTO_UNKNOWN;
            f->alflags |= FLOW_AL_PROTO_DETECT_DONE;

            r = AppLayerParse(f, alproto, f->alflags,
                           p->payload, p->payload_len);
        } else {
            f->alflags |= FLOW_AL_PROTO_DETECT_DONE;
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
            r = AppLayerParse(f, alproto, f->alflags,
                        p->payload, p->payload_len);
        } else {
            SCLogDebug(" udp session not start, but no l7 data? Weird");
        }
    }

    SCMutexUnlock(&f->m);
    SCReturnInt(r);
}

