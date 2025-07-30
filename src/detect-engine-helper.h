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
#include "detect-engine-inspect-buffer.h"

// type from flow.h with only forward declarations for bindgen
typedef struct Flow_ Flow;
// types from detect.h with only forward declarations for bindgen
// could be #ifndef SURICATA_BINDGEN_H #include "detect.h" #endif
typedef struct DetectEngineCtx_ DetectEngineCtx;
typedef struct Signature_ Signature;
typedef struct SigMatchCtx_ SigMatchCtx;
typedef struct DetectEngineThreadCtx_ DetectEngineThreadCtx;
typedef struct DetectEngineTransforms DetectEngineTransforms;
typedef InspectionBuffer *(*InspectionBufferGetDataPtr)(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
typedef bool (*InspectionMultiBufferGetDataPtr)(struct DetectEngineThreadCtx_ *det_ctx,
        const void *txv, const uint8_t flow_flags, uint32_t local_id, const uint8_t **buf,
        uint32_t *buf_len);
typedef bool (*InspectionSingleBufferGetDataPtr)(
        const void *txv, const uint8_t flow_flags, const uint8_t **buf, uint32_t *buf_len);

/// App-layer light version of SigTableElmt
typedef struct SCSigTableAppLiteElmt {
    /// keyword name
    const char *name;
    /// keyword description
    const char *desc;
    /// keyword documentation url
    const char *url;
    /// flags SIGMATCH_*
    uint32_t flags;
    /// function callback to parse and setup keyword in rule
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);
    /// function callback to free structure allocated by setup if any
    void (*Free)(DetectEngineCtx *, void *);
    /// function callback to match on an app-layer transaction
    int (*AppLayerTxMatch)(DetectEngineThreadCtx *, Flow *, uint8_t flags, void *alstate, void *txv,
            const Signature *, const SigMatchCtx *);
} SCSigTableAppLiteElmt;

typedef struct SCTransformTableElmt {
    const char *name;
    const char *desc;
    const char *url;
    uint32_t flags;
    int (*Setup)(DetectEngineCtx *, Signature *, const char *);
    void (*Free)(DetectEngineCtx *, void *);
    void (*Transform)(DetectEngineThreadCtx *, InspectionBuffer *, void *context);
    bool (*TransformValidate)(const uint8_t *content, uint16_t content_len, void *context);
    void (*TransformId)(const uint8_t **id_data, uint32_t *id_length, void *context);
} SCTransformTableElmt;

int SCDetectHelperNewKeywordId(void);

uint16_t SCDetectHelperKeywordRegister(const SCSigTableAppLiteElmt *kw);
void SCDetectHelperKeywordAliasRegister(uint16_t kwid, const char *alias);
int SCDetectHelperBufferRegister(const char *name, AppProto alproto, uint8_t direction);

int SCDetectHelperBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        uint8_t direction, InspectionSingleBufferGetDataPtr GetData);
int SCDetectHelperMultiBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        uint8_t direction, InspectionMultiBufferGetDataPtr GetData);
int SCDetectHelperMultiBufferProgressMpmRegister(const char *name, const char *desc,
        AppProto alproto, uint8_t direction, InspectionMultiBufferGetDataPtr GetData, int progress);

int SCDetectHelperTransformRegister(const SCTransformTableElmt *kw);

#endif /* SURICATA_DETECT_ENGINE_HELPER_H */
