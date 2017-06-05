/* Copyright (C) 2013-2016 Open Information Security Foundation
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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Based on detect-engine-uri.c
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-dns-common.h"
#include "detect-engine-dns.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#ifdef HAVE_RUST
#include "rust-dns-dns-gen.h"
#endif

/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f Flow
 *  \param flags app layer flags
 *  \param state App layer state
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
int DetectEngineInspectDnsQueryName(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    uint8_t *buffer;
    uint32_t buffer_len;
    int r = 0;

    SCLogDebug("start");

#ifdef HAVE_RUST
    for (uint16_t i = 0;; i++) {
        det_ctx->discontinue_matching = 0;
        det_ctx->buffer_offset = 0;
        det_ctx->inspection_recursion_counter = 0;

        if (rs_dns_tx_get_query_name(txv, i, &buffer, &buffer_len)) {
            r = DetectEngineContentInspection(de_ctx, det_ctx,
                s, smd, f, buffer, buffer_len, 0,
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
            if (r == 1) {
                break;
            }
        } else {
            break;
        }
    }
#else
    DNSTransaction *tx = (DNSTransaction *)txv;
    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &tx->query_list, next) {
        SCLogDebug("tx %p query %p", tx, query);
        det_ctx->discontinue_matching = 0;
        det_ctx->buffer_offset = 0;
        det_ctx->inspection_recursion_counter = 0;

        buffer = (uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry));
        buffer_len = query->len;

        //PrintRawDataFp(stdout, buffer, buffer_len);

        r = DetectEngineContentInspection(de_ctx, det_ctx,
                s, smd,
                f, buffer, buffer_len, 0,
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
        if (r == 1)
            break;
    }
#endif
    return r;
}

/** \brief DNS Query Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxDnsQuery(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();
    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;

#ifdef HAVE_RUST
    uint8_t *buffer;
    uint32_t buffer_len;
    for (uint16_t i = 0; i < 0xffff; i++) {
        if (rs_dns_tx_get_query_name(txv, i, &buffer, &buffer_len)) {
            if (buffer_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer, buffer_len);
            }
        } else {
            break;
        }
    }
#else
    DNSTransaction *tx = (DNSTransaction *)txv;
    DNSQueryEntry *query = NULL;

    TAILQ_FOREACH(query, &tx->query_list, next) {
        SCLogDebug("tx %p query %p", tx, query);

        const uint8_t *buffer =
            (const uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry));
        const uint32_t buffer_len = query->len;

        if (buffer_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer, buffer_len);
        }
    }
#endif
}

int PrefilterTxDnsQueryRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxDnsQuery,
        ALPROTO_DNS, 1,
        mpm_ctx, NULL, "dns_query");
}

int DetectEngineInspectDnsRequest(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

int DetectEngineInspectDnsResponse(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}
