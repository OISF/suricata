/* Copyright (C) 2007-2016 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"

typedef struct PrefilterPacketHeaderHashCtx_ {
    PrefilterPacketHeaderValue v1;

    uint16_t type;  /**< PREFILTER_EXTRA_MATCH_* */
    uint16_t value;

    uint32_t cnt;
} PrefilterPacketHeaderHashCtx;

static uint32_t PrefilterPacketHeaderHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    PrefilterPacketHeaderCtx *ctx = data;
    uint64_t hash = ctx->v1.u64[0] + ctx->v1.u64[1] + ctx->type + ctx->value;
    hash %= ht->array_size;
    return hash;
}

static char PrefilterPacketHeaderCompareFunc(void *data1, uint16_t len1,
                                       void *data2, uint16_t len2)
{
    PrefilterPacketHeaderHashCtx *ctx1 = data1;
    PrefilterPacketHeaderHashCtx *ctx2 = data2;
    return (ctx1->v1.u64[0] == ctx2->v1.u64[0] &&
            ctx1->v1.u64[1] == ctx2->v1.u64[1] &&
            ctx1->type == ctx2->type &&
            ctx1->value == ctx2->value);
}

static void PrefilterPacketHeaderFreeFunc(void *ptr)
{
    SCFree(ptr);
}

static void PrefilterPacketHeaderFree(void *pectx)
{
    PrefilterPacketHeaderCtx *ctx = pectx;
    SCFree(ctx->sigs_array);
    SCFree(ctx);
}

static void PrefilterPacketU8HashCtxFree(void *vctx)
{
    PrefilterPacketU8HashCtx *ctx = vctx;
    int i;
    for (i = 0; i < 256; i++) {
        SigsArray *sa = ctx->array[i];
        if (sa == NULL)
            continue;
        SCFree(sa->sigs);
        SCFree(sa);
    }
    SCFree(ctx);
}

static void GetExtraMatch(const Signature *s, uint16_t *type, uint16_t *value)
{
    if (s->sp != NULL && s->sp->next == NULL && s->sp->port == s->sp->port2 &&
        !(s->sp->flags & PORT_FLAG_NOT))
    {
        *type = PREFILTER_EXTRA_MATCH_SRCPORT;
        *value = s->sp->port;
    } else if (s->alproto != ALPROTO_UNKNOWN) {
        *type = PREFILTER_EXTRA_MATCH_ALPROTO;
        *value = s->alproto;
    } else if (s->dp != NULL && s->dp->next == NULL && s->dp->port == s->dp->port2 &&
        !(s->dp->flags & PORT_FLAG_NOT))
    {
        *type = PREFILTER_EXTRA_MATCH_DSTPORT;
        *value = s->dp->port;
    }
}

/** \internal
 */
static int
SetupEngineForPacketHeader(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        int sm_type, PrefilterPacketHeaderHashCtx *hctx,
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx))
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint32_t sig_offset = 0;

    PrefilterPacketHeaderCtx *ctx = SCCalloc(1, sizeof(PrefilterPacketHeaderCtx));
    if (ctx == NULL)
        return -1;

    ctx->v1 = hctx->v1;
    ctx->type = hctx->type;
    ctx->value = hctx->value;

    ctx->sigs_cnt = hctx->cnt;
    ctx->sigs_array = SCCalloc(ctx->sigs_cnt, sizeof(SigIntId));
    if (ctx->sigs_array == NULL) {
        SCFree(ctx);
        return -1;
    }

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;
        if (s->init_data->prefilter_sm == NULL || s->init_data->prefilter_sm->type != sm_type)
            continue;

        uint16_t type = 0;
        uint16_t value = 0;
        GetExtraMatch(s, &type, &value);

        if (Compare(ctx->v1, s->init_data->prefilter_sm->ctx) &&
            ctx->type == type && ctx->value == value)
        {
            SCLogDebug("appending sid %u on %u", s->id, sig_offset);
            ctx->sigs_array[sig_offset] = s->num;
            sig_offset++;

            s->flags |= SIG_FLAG_PREFILTER;
        }
    }

    SCLogDebug("%s: ctx %p extra type %u extra value %u, sig cnt %u",
            sigmatch_table[sm_type].name, ctx, ctx->type, ctx->value,
            ctx->sigs_cnt);
    PrefilterAppendEngine(de_ctx, sgh, Match, ctx,
            PrefilterPacketHeaderFree, sigmatch_table[sm_type].name);
    return 0;
}

/** \internal
 *  \brief apply signature to each value */
static void ApplyToU8Hash(PrefilterPacketU8HashCtx *ctx, PrefilterPacketHeaderValue v, Signature *s)
{
    switch (v.u8[0]) {
        case PREFILTER_U8HASH_MODE_EQ:
            {
                SigsArray *sa = ctx->array[v.u8[1]];
                sa->sigs[sa->offset++] = s->num;
                break;
            }
        case PREFILTER_U8HASH_MODE_LT:
            {
                uint8_t x = v.u8[1] - 1;
                do {
                    SigsArray *sa = ctx->array[x];
                    sa->sigs[sa->offset++] = s->num;
                } while (x--);

                break;
        }
        case DetectUintModeLte: {
            uint8_t x = v.u8[1];
            do {
                SigsArray *sa = ctx->array[x];
                sa->sigs[sa->offset++] = s->num;
            } while (x--);

            break;
        }
        case PREFILTER_U8HASH_MODE_GT:
            {
                int x = v.u8[1] + 1;
                do {
                    SigsArray *sa = ctx->array[x];
                    sa->sigs[sa->offset++] = s->num;
                } while (++x < 256);

                break;
        }
        case DetectUintModeGte: {
            int x = v.u8[1];
            do {
                SigsArray *sa = ctx->array[x];
                sa->sigs[sa->offset++] = s->num;
            } while (++x < 256);

            break;
        }
        case PREFILTER_U8HASH_MODE_RA:
            {
                int x = v.u8[1] + 1;
                do {
                    SigsArray *sa = ctx->array[x];
                    sa->sigs[sa->offset++] = s->num;
                } while (++x < v.u8[2]);

                break;
        }
        case DetectUintModeNe: {
            for (uint8_t i = 0; i < UINT8_MAX; i++) {
                if (i != v.u8[1]) {
                    SigsArray *sa = ctx->array[i];
                    sa->sigs[sa->offset++] = s->num;
                }
            }
            if (UINT8_MAX != v.u8[1]) {
                SigsArray *sa = ctx->array[UINT8_MAX];
                sa->sigs[sa->offset++] = s->num;
            }
            break;
        }
    }
}

/** \internal
 *  \brief turn values into a u8 hash map
 *  \todo improve error handling
 *  \todo deduplicate sigs arrays
 */
static int
SetupEngineForPacketHeaderPrefilterPacketU8HashCtx(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type, uint32_t *counts,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx))
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint32_t cnt = 0;

    PrefilterPacketU8HashCtx *ctx = SCCalloc(1, sizeof(PrefilterPacketU8HashCtx));
    if (ctx == NULL)
        return -1;

    int set_cnt = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0)
            continue;
        ctx->array[i] = SCCalloc(1, sizeof(SigsArray));
        BUG_ON(ctx->array[i] == NULL);

        ctx->array[i]->cnt = counts[i];
        ctx->array[i]->sigs = SCCalloc(ctx->array[i]->cnt, sizeof(SigIntId));
        BUG_ON(ctx->array[i]->sigs == NULL);
        set_cnt++;
    }
    if (set_cnt == 0) {
        /* not an error */
        PrefilterPacketU8HashCtxFree(ctx);
        return 0;
    }

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;
        if (s->init_data->prefilter_sm == NULL || s->init_data->prefilter_sm->type != sm_type)
            continue;

        PrefilterPacketHeaderValue v;
        memset(&v, 0, sizeof(v));
        Set(&v, s->init_data->prefilter_sm->ctx);

        ApplyToU8Hash(ctx, v, s);
        s->flags |= SIG_FLAG_PREFILTER;
        cnt++;
    }

    if (cnt) {
        PrefilterAppendEngine(de_ctx, sgh, Match, ctx,
                PrefilterPacketU8HashCtxFree,
                sigmatch_table[sm_type].name);
    } else {
        PrefilterPacketU8HashCtxFree(ctx);
    }
    return 0;
}

/** \internal
 *  \brief setup a engine for each unique value
 */
static void SetupSingle(DetectEngineCtx *de_ctx, HashListTable *hash_table,
        SigGroupHead *sgh, int sm_type,
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx))
{
    HashListTableBucket *hb = HashListTableGetListHead(hash_table);
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        PrefilterPacketHeaderHashCtx *ctx = HashListTableGetListData(hb);

        SetupEngineForPacketHeader(de_ctx, sgh, sm_type,
                ctx, Compare, Match);
    }
}

/** \internal
 *  \brief setup a single engine with a hash map for u8 values
 */
static void SetupU8Hash(DetectEngineCtx *de_ctx, HashListTable *hash_table,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
            Packet *p, const void *pectx))
{
    uint32_t counts[256];
    memset(&counts, 0, sizeof(counts));

    HashListTableBucket *hb = HashListTableGetListHead(hash_table);
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        PrefilterPacketHeaderHashCtx *ctx = HashListTableGetListData(hb);

        switch (ctx->v1.u8[0]) {
            case PREFILTER_U8HASH_MODE_EQ:
                counts[ctx->v1.u8[1]] += ctx->cnt;
                break;
            case PREFILTER_U8HASH_MODE_LT:
            {
                uint8_t v = ctx->v1.u8[1];
                while (v > 0) {
                    v--;
                    counts[v] += ctx->cnt;
                }

                break;
            }
            case DetectUintModeLte: {
                uint8_t v = ctx->v1.u8[1];
                counts[v] += ctx->cnt;
                while (v > 0) {
                    v--;
                    counts[v] += ctx->cnt;
                }

                break;
            }
            case PREFILTER_U8HASH_MODE_GT:
            {
                uint8_t v = ctx->v1.u8[1];
                while (v < UINT8_MAX) {
                    v++;
                    counts[v] += ctx->cnt;
                }

                break;
            }
            case DetectUintModeGte: {
                uint8_t v = ctx->v1.u8[1];
                counts[v] += ctx->cnt;
                while (v < UINT8_MAX) {
                    v++;
                    counts[v] += ctx->cnt;
                }

                break;
            }
            case PREFILTER_U8HASH_MODE_RA:
            {
                if (ctx->v1.u8[1] < ctx->v1.u8[2]) {
                    // ctx->v1.u8[1] is not UINT8_MAX
                    uint8_t v = ctx->v1.u8[1] + 1;
                    while (v < ctx->v1.u8[2]) {
                        counts[v] += ctx->cnt;
                        v++;
                    }
                }
                break;
            }
            case DetectUintModeNe: {
                for (uint8_t i = 0; i < UINT8_MAX; i++) {
                    if (i != ctx->v1.u8[1]) {
                        counts[i] += ctx->cnt;
                    }
                }
                if (UINT8_MAX != ctx->v1.u8[1]) {
                    counts[UINT8_MAX] += ctx->cnt;
                }
                break;
            }
            default:
                SCLogWarning("Prefilter not implemented for mode 0x%x", ctx->v1.u8[0]);
        }
    }

    SetupEngineForPacketHeaderPrefilterPacketU8HashCtx(de_ctx, sgh, sm_type,
            counts, Set, Compare, Match);
}

static int PrefilterSetupPacketHeaderCommon(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
                      Packet *p, const void *pectx),
        bool u8hash)
{
    Signature *s = NULL;
    uint32_t sig = 0;

    if (sgh == NULL)
        return 0;

    /* first count how many engines we will need */

    HashListTable *hash_table = HashListTableInit(4096,
            PrefilterPacketHeaderHashFunc,
            PrefilterPacketHeaderCompareFunc,
            PrefilterPacketHeaderFreeFunc);
    if (hash_table == NULL)
        return -1;

    for (sig = 0; sig < sgh->init->sig_cnt; sig++) {
        s = sgh->init->match_array[sig];
        if (s == NULL)
            continue;
        if (s->init_data->prefilter_sm == NULL || s->init_data->prefilter_sm->type != sm_type)
            continue;

        PrefilterPacketHeaderHashCtx ctx;
        memset(&ctx, 0, sizeof(ctx));
        Set(&ctx.v1, s->init_data->prefilter_sm->ctx);

        GetExtraMatch(s, &ctx.type, &ctx.value);

        PrefilterPacketHeaderHashCtx *rctx = HashListTableLookup(hash_table, (void *)&ctx, 0);
        if (rctx != 0) {
            rctx->cnt++;
        } else {
            PrefilterPacketHeaderHashCtx *actx = SCCalloc(1, sizeof(*actx));
            if (actx == NULL)
                goto error;

            Set(&actx->v1, s->init_data->prefilter_sm->ctx);
            actx->cnt = 1;
            actx->type = ctx.type;
            actx->value = ctx.value;

            int ret = HashListTableAdd(hash_table, actx, 0);
            if (ret != 0) {
                SCFree(actx);
                goto error;
            }
        }
    }

    if (!u8hash) {
        SetupSingle(de_ctx, hash_table, sgh, sm_type, Compare, Match);
    } else {
        SetupU8Hash(de_ctx, hash_table, sgh, sm_type, Set, Compare, Match);
    }

    HashListTableFree(hash_table);
    return 0;
error:
    HashListTableFree(hash_table);
    return -1;
}

int PrefilterSetupPacketHeaderU8Hash(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
                      Packet *p, const void *pectx))
{
    return PrefilterSetupPacketHeaderCommon(de_ctx, sgh, sm_type, Set, Compare, Match, true);
}

int PrefilterSetupPacketHeader(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx))
{
    return PrefilterSetupPacketHeaderCommon(de_ctx, sgh, sm_type, Set, Compare, Match, false);
}
