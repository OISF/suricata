/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __DETECT_ENGINE_PREFILTER_COMMON_H__
#define __DETECT_ENGINE_PREFILTER_COMMON_H__

#include "rust.h"

typedef union {
    uint8_t u8[16];
    uint16_t u16[8];
    uint32_t u32[4];
    uint64_t u64[2];
} PrefilterPacketHeaderValue;

#define PREFILTER_EXTRA_MATCH_UNUSED  0
#define PREFILTER_EXTRA_MATCH_ALPROTO 1
#define PREFILTER_EXTRA_MATCH_SRCPORT 2
#define PREFILTER_EXTRA_MATCH_DSTPORT 3

typedef struct PrefilterPacketHeaderCtx_ {
    PrefilterPacketHeaderValue v1;

    uint16_t type;
    uint16_t value;

    /** rules to add when the flags are present */
    uint32_t sigs_cnt;
    SigIntId *sigs_array;
} PrefilterPacketHeaderCtx;

typedef struct SigsArray_ {
    SigIntId *sigs;
    uint32_t cnt;
    uint32_t offset; // used to track assign pos
} SigsArray;

typedef struct PrefilterPacketU8HashCtx_ {
    SigsArray *array[256];
} PrefilterPacketU8HashCtx;

#define PREFILTER_U8HASH_MODE_EQ DetectUintModeEqual
#define PREFILTER_U8HASH_MODE_LT DetectUintModeLt
#define PREFILTER_U8HASH_MODE_GT DetectUintModeGt
#define PREFILTER_U8HASH_MODE_RA DetectUintModeRange

int PrefilterSetupPacketHeader(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx));

int PrefilterSetupPacketHeaderU8Hash(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx));

static inline bool
PrefilterPacketHeaderExtraMatch(const PrefilterPacketHeaderCtx *ctx,
                                const Packet *p)
{
    switch (ctx->type)
    {
        case PREFILTER_EXTRA_MATCH_UNUSED:
            break;
        case PREFILTER_EXTRA_MATCH_ALPROTO:
            if (p->flow == NULL || !AppProtoEquals(ctx->value, p->flow->alproto))
                return false;
            break;
        case PREFILTER_EXTRA_MATCH_SRCPORT:
            if (p->sp != ctx->value)
                return false;
            break;
        case PREFILTER_EXTRA_MATCH_DSTPORT:
            if (p->dp != ctx->value)
                return false;
            break;
    }
    return true;
}

static inline bool PrefilterIsPrefilterableById(const Signature *s, enum DetectKeywordId kid)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        if (sm->type == kid) {
            return true;
        }
    }
    return false;
}

#endif /* __DETECT_ENGINE_PREFILTER_COMMON_H__ */
