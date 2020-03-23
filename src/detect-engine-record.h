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

#include "app-layer-records.h"

void PrefilterRecords(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t flags, const AppProto alproto);
int PrefilterGenericMpmRecordRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);
bool DetectEngineRecordInspectionRun(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f, Packet *p, uint8_t *alert_flags);
InspectionBuffer *DetectRecord2InspectBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const Records *recs, const Record *rec, const int list_id,
        const uint32_t idx, const bool first);
int DetectEngineInspectRecordBufferGeneric(DetectEngineThreadCtx *det_ctx,
        const DetectEngineRecordInspectionEngine *engine, const Signature *s, Packet *p,
        const Records *recs, const Record *rec, const uint32_t idx);
