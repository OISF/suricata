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
#include "util-debug.h"

/** \brief Get the active app layer proto from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval proto (ALPROTO_UNKNOWN if no proto yet) */
uint16_t AppLayerGetProtoFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    SCReturnUInt(ssn->alproto);
}

/** \brief Get the active app layer state from the packet
 *  \param p packet pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromPacket(Packet *p) {
    SCEnter();

    if (p == NULL || p->flow == NULL) {
        SCReturnPtr(NULL, "void");
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL || ssn->aldata == NULL) {
        SCReturnPtr(NULL, "void");
    }

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];

    SCLogDebug("p->flow %p", p->flow);
    SCReturnPtr(alstate, "void");
}

/** \brief Get the active app layer state from the flow
 *  \param f flow pointer
 *  \retval alstate void pointer to the state
 *  \retval NULL in case we have no state */
void *AppLayerGetProtoStateFromFlow(Flow *f) {
    SCEnter();

    if (f == NULL)
        SCReturnPtr(NULL, "void");

    TcpSession *ssn = (TcpSession *)f->protoctx;
    if (ssn == NULL || ssn->aldata == NULL)
        SCReturnPtr(NULL, "void");

    SCLogDebug("ssn->alproto %"PRIu16"", ssn->alproto);

    void *alstate = ssn->aldata[AlpGetStateIdx(ssn->alproto)];
    SCReturnPtr(alstate, "void");
}

/** global app layer detection context */
extern AlpProtoDetectCtx alp_proto_ctx;

/**
 *  \brief Handle a app layer message
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

    TcpSession *ssn = smsg->flow->protoctx;
    if (ssn != NULL) {
        alproto = ssn->alproto;

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
                            smsg->data.data, smsg->data.data_len, smsg->flags);
            if (alproto != ALPROTO_UNKNOWN) {
                /* store the proto and setup the L7 data array */
                StreamL7DataPtrInit(ssn);
                ssn->alproto = alproto;
                ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

                r = AppLayerParse(smsg->flow, alproto, smsg->flags,
                               smsg->data.data, smsg->data.data_len);
            } else {
                if (smsg->flags & STREAM_TOSERVER) {
                    if (smsg->data.data_len >= alp_proto_ctx.toserver.max_len) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                        StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
                    }
                } else if (smsg->flags & STREAM_TOCLIENT) {
                    if (smsg->data.data_len >= alp_proto_ctx.toclient.max_len) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
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

    /* flow is free again */
    smsg->flow->use_cnt--;

    /* return the used message to the queue */
    StreamMsgReturnToPool(smsg);

    SCReturnInt(r);
}

