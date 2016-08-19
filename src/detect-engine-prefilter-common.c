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

    uint32_t cnt;
} PrefilterPacketHeaderHashCtx;

static uint32_t PrefilterPacketHeaderHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    PrefilterPacketHeaderCtx *ctx = data;
    uint64_t hash = ctx->v1.u64;
    hash %= ht->array_size;
    return hash;
}

static char PrefilterPacketHeaderCompareFunc(void *data1, uint16_t len1,
                                       void *data2, uint16_t len2)
{
    PrefilterPacketHeaderHashCtx *ctx1 = data1;
    PrefilterPacketHeaderHashCtx *ctx2 = data2;
    return (ctx1->v1.u64 == ctx2->v1.u64);
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

/** \internal
 */
static int
SetupEngineForPacketHeader(SigGroupHead *sgh, int sm_type,
        PrefilterPacketHeaderValue v, uint32_t count,
        _Bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx))
{
    Signature *s = NULL;
    uint32_t sig = 0;
    uint32_t sig_offset = 0;

    PrefilterPacketHeaderCtx *ctx = SCCalloc(1, sizeof(PrefilterPacketHeaderCtx));
    if (ctx == NULL)
        return -1;

    ctx->v1 = v;
    ctx->sigs_cnt = count;
    ctx->sigs_array = SCCalloc(ctx->sigs_cnt, sizeof(SigIntId));
    if (ctx->sigs_array == NULL) {
        SCFree(ctx);
        return -1;
    }

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;
        /* for now simply ignore sigs in mpm */
        if (s->mpm_sm != NULL)
            continue;
        if (s->prefilter_sm == NULL || s->prefilter_sm->type != sm_type)
            continue;

        if (Compare(v, s->prefilter_sm->ctx)) {
            SCLogDebug("appending sid %u on %u", s->id, sig_offset);
            ctx->sigs_array[sig_offset] = s->num;
            sig_offset++;

            s->flags |= SIG_FLAG_PREFILTER;
        }
    }

    PrefilterAppendEngine(sgh, Match, ctx, PrefilterPacketHeaderFree);
    return 0;
}

int PrefilterSetupPacketHeader(SigGroupHead *sgh, int sm_type,
        void (*Set)(PrefilterPacketHeaderValue *v, void *),
        _Bool (*Compare)(PrefilterPacketHeaderValue v, void *),
        void (*Match)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx))
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

    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        s = sgh->match_array[sig];
        if (s == NULL)
            continue;
        /* for now simply ignore sigs in mpm */
        if (s->mpm_sm != NULL)
            continue;
        if (s->prefilter_sm == NULL || s->prefilter_sm->type != sm_type)
            continue;

        PrefilterPacketHeaderHashCtx ctx;
        memset(&ctx, 0, sizeof(ctx));
        Set(&ctx.v1, s->prefilter_sm->ctx);

        PrefilterPacketHeaderHashCtx *rctx = HashListTableLookup(hash_table, (void *)&ctx, 0);
        if (rctx != 0) {
            rctx->cnt++;
        } else {
            PrefilterPacketHeaderHashCtx *actx = SCCalloc(1, sizeof(*actx));
            if (actx == NULL)
                goto error;

            Set(&actx->v1, s->prefilter_sm->ctx);
            actx->cnt = 1;

            int ret = HashListTableAdd(hash_table, actx, 0);
            if (ret != 0) {
                SCFree(actx);
                goto error;
            }
        }
    }

    // for each ack value, do
    HashListTableBucket *hb = HashListTableGetListHead(hash_table);
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        PrefilterPacketHeaderHashCtx *ctx = HashListTableGetListData(hb);

        SetupEngineForPacketHeader(sgh, sm_type,
                ctx->v1, ctx->cnt,
                Compare, Match);
    }

    HashListTableFree(hash_table);
    return 0;
error:
    HashListTableFree(hash_table);
    return -1;
}


