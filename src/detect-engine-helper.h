/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 */

#ifndef SURICATA_DETECT_ENGINE_HELPER_H
#define SURICATA_DETECT_ENGINE_HELPER_H

#include "app-layer-protos.h"
#include "detect.h"
#include "rust.h"

int DetectHelperKeywordRegister(const SCSigTableElmt *kw);

typedef struct SCPluginTransformTableElmt {
    const char *name;
    const char *desc;
    uint16_t flags;
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);
    void (*Free)(DetectEngineCtx *, void *);
    void (*Transform)(InspectionBuffer *buffer, void *options);
} SCPluginTransformTableElmt;

int DetectHelperTransformRegister(const SCPluginTransformTableElmt *kw);
int DetectHelperBufferRegister(const char *name, AppProto alproto, bool toclient, bool toserver);

typedef bool (*SimpleGetTxBuffer)(void *, uint8_t, const uint8_t **, uint32_t *);
typedef bool (*MultiGetTxBuffer)(void *, uint8_t, uint32_t, const uint8_t **, uint32_t *);

InspectionBuffer *DetectHelperGetData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id, SimpleGetTxBuffer GetBuf);
int DetectHelperBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        bool toclient, bool toserver, InspectionBufferGetDataPtr GetData);

InspectionBuffer *DetectHelperGetMultiData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id, uint32_t index, MultiGetTxBuffer GetBuf);

#endif /* SURICATA_DETECT_ENGINE_HELPER_H */
