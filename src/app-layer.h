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
 */

#ifndef __APP_LAYER__H__
#define __APP_LAYER__H__

#include "flow.h"
#include "decode.h"

#include "stream-tcp.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "stream.h"

/* global app layer protocol detection context, defined and maintained
 * by the app-layer.c function.  If anyone wants access to this variable
 * they need to use this header file. */
extern void *alpd_ctx;

#define APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER \
    (~STREAM_TOSERVER & ~STREAM_TOCLIENT)

int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, Flow *f,
                          TcpSession *ssn, TcpStream *stream, uint8_t *data, uint32_t data_len, Packet *p, uint8_t flags);
int AppLayerHandleTCPMsg(AlpProtoDetectThreadCtx *, StreamMsg *);
int AppLayerHandleUdp(AlpProtoDetectThreadCtx *, Flow *, Packet *p);

/***** Anoop *****/

/**
 * \brief Setup the app layer.
 *
 *        Includes protocol detection setup and the protocol parser setup.
 */
int AppLayerSetup(void);

/**
 * \brief Creates a new app layer thread context.
 *
 * \retval On success, pointer to the newly create thread context;
 *         On failure, NULL.
 */
void *AppLayerGetCtxThread(void);

/**
 * \brief Destroys the context created by AppLayerDestroyCtxThread.
 *
 * \param tctx Pointer to the thread context to destroy.
 */
void AppLayerDestoryCtxThread(void *tctx);

/**
 * \brief Registers the app layer unittests.
 */
void AppLayerRegisterUnittests(void);

/**
 * \brief Get the active app layer proto from the packet.
 *        This function requires that the flow (p->flow) be locked.
 *
 * \param p Packet pointer with a LOCKED flow.
 *
 * \retval proto On success a valid protocol from the AppProto table.
 *               If no proto is set for the flow yet, ALPROTO_UNKNOWN.
 */
uint16_t AppLayerGetProtoFromPacket(Packet *p);

/**
 * \brief Get the active app layer state from the packet.
 *        This function requires that the flow (p->flow) be locked.
 *
 * \param p Packet pointer with a LOCKED flow.
 *
 * \retval On success, a valid pointer to the app layer state;
 *         If there is no state, NULL.
 */
void *AppLayerGetProtoStateFromPacket(Packet *);

/**
 * \brief Get the active app layer state from the flow.
 *        This function requires that the flow (p->flow) be locked.
 *
 * \param f Flow pointer to a LOCKED flow
 *
 * \retval proto On success a valid protocol from the AppProto table.
 *               If no proto is set for the flow yet, ALPROTO_UNKNOWN.
 */
void *AppLayerGetProtoStateFromFlow(Flow *f);

/**
 * \brief Handle a chunk of reassembled TCP data.
 *
 *        If the protocol is not known, the proto detection code is run first.

 *        During detection this function can call the stream reassembly,
 *        inline or non-inline for the opposing direction, while already
 *        being called by the same stream reassembly for a particular
 *        direction.  This should cause any issues, since processing of
 *        each stream is independent of the other stream.
 *
 * \param tv Pointer to the thread context.
 * \param dp_ctx The upper layer stream reassembly, per thread context.
 * \param f Flow pointer(shouldn't be locked).
 * \param ssn TCP Session pointer.
 * \param data Pointer to reassembled data.
 * \param data_len Length of the above data chunk.
 * \param flags Control flags.
 *
 * \retval  0 On success.
 *         -1 On failure.
 */
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                          Flow *f, TcpSession *ssn, TcpStream *stream,
                          uint8_t *data, uint32_t data_len,
                          Packet *p, uint8_t flags);

#endif /* __APP_LAYER__H__ */
