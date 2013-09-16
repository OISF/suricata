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

#ifndef __APP_LAYER_H__
#define __APP_LAYER_H__

#include "flow.h"
#include "decode.h"

#include "stream-tcp.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "stream.h"

#define APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER (~STREAM_TOSERVER & ~STREAM_TOCLIENT)

uint16_t AppLayerGetProtoFromPacket(Packet *);
void *AppLayerGetProtoStateFromPacket(Packet *);
void *AppLayerGetProtoStateFromFlow(Flow *);
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx, Flow *f,
                          TcpSession *ssn, TcpStream *stream, uint8_t *data, uint32_t data_len, Packet *p, uint8_t flags);
int AppLayerHandleTCPMsg(AlpProtoDetectThreadCtx *, StreamMsg *);
//int AppLayerHandleMsg(AlpProtoDetectThreadCtx *, StreamMsg *);
int AppLayerHandleUdp(AlpProtoDetectThreadCtx *, Flow *, Packet *p);

void AppLayerRegisterUnittests(void);

#endif /* __APP_LAYER_H__ */

