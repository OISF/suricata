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

#ifndef __APP_LAYER_DETECT_PROTO_H__
#define __APP_LAYER_DETECT_PROTO_H__

#include "stream.h"

typedef struct AlpProtoDetectDirectionThread_ {
    MpmThreadCtx mpm_ctx;
    PatternMatcherQueue pmq;
} AlpProtoDetectDirectionThread;

typedef struct AlpProtoDetectThreadCtx_ {
    AlpProtoDetectDirectionThread toserver;
    AlpProtoDetectDirectionThread toclient;
} AlpProtoDetectThreadCtx;

int AppLayerHandleMsg(AlpProtoDetectThreadCtx *, StreamMsg *smsg);
void *AppLayerDetectProtoThread(void *td);

void AppLayerDetectProtoThreadInit(void);

void AppLayerDetectProtoThreadSpawn(void);
void AlpDetectRegisterTests(void);

void AlpProtoFinalize2Thread(AlpProtoDetectThreadCtx *);
void AlpProtoDeFinalize2Thread (AlpProtoDetectThreadCtx *);
void AlpProtoDestroy(void);

#endif /* __APP_LAYER_DETECT_PROTO_H__ */

