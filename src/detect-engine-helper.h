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

#ifndef __DETECT_ENGINE_HELPER_H
#define __DETECT_ENGINE_HELPER_H

#include "app-layer-protos.h"
#include "detect.h"

// Structure for keyword dynamic registration by plugin
typedef struct SCPluginSigTableElmt {
    const char *name;
    const char *desc;
    uint16_t flags;
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);
    void (*Free)(DetectEngineCtx *, void *);
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *, uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);
} SCPluginSigTableElmt;

int DetectHelperKeywordRegister(const SCPluginSigTableElmt *kw);
int DetectHelperBufferRegister(const char *name, AppProto alproto, bool toclient, bool toserver);

typedef bool (*SimpleGetTxBuffer)(void *, uint8_t, const uint8_t **, uint32_t *);

int DetectHelperKeywordSetup(DetectEngineCtx *de_ctx, AppProto alproto, uint16_t kw_id, int buf_id,
        Signature *s, void *ctx);
InspectionBuffer *DetectHelperGetData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id, SimpleGetTxBuffer GetBuf);
int DetectHelperBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        bool toclient, bool toserver, InspectionBufferGetDataPtr GetData);

#endif /* __DETECT_ENGINE_HELPER_H */
