/* Copyright (C) 2021 Open Information Security Foundation
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
 */

#include "rust.h"
#include "app-layer-frames.h"

void DetectRunPrefilterFrame(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const Frames *frames, const Frame *frame, const AppProto alproto);
bool DetectRunFrameInspectRule(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p, const Frames *frames, const Frame *frame);

int DetectEngineInspectFrameBufferGeneric(DetectEngineThreadCtx *det_ctx,
        const DetectEngineFrameInspectionEngine *engine, const Signature *s, Packet *p,
        const Frames *frames, const Frame *frame);
