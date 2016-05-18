/* Copyright (C) 2016 Open Information Security Foundation
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
 *  \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-ssl.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

/**
 * \brief TLS sni match -- searches for one pattern per signature.
 *
 * \param det_ctx   Detection engine thread ctx
 * \param hrh       Buffer to inspect
 * \param hrh_len   Buffer length
 * \param flags     Flags
 *
 * \retval ret      Number of matches
 */
static inline uint32_t TlsSniPatternSearch(DetectEngineThreadCtx *det_ctx,
                                           const uint8_t *buffer,
                                           const uint32_t buffer_len,
                                           const uint8_t flags)
{
    SCEnter();

    uint32_t ret = 0;

    DEBUG_VALIDATE_BUG_ON(flags & STREAM_TOCLIENT);
    DEBUG_VALIDATE_BUG_ON(det_ctx->sgh->mpm_tlssni_ctx_ts == NULL);

    if (buffer_len >= det_ctx->sgh->mpm_tlssni_ctx_ts->minlen) {
        ret = mpm_table[det_ctx->sgh->mpm_tlssni_ctx_ts->mpm_type].
            Search(det_ctx->sgh->mpm_tlssni_ctx_ts, &det_ctx->mtcu,
                    &det_ctx->pmq, buffer, buffer_len);
    }

    SCReturnUInt(ret);
}

/**
 *  \brief Run the pattern matcher against the SNI buffer
 *
 *  \param det_ctx    Detection engine thread ctx
 *  \param f          Locked flow
 *  \param dns_state  Initialized dns state
 *  \param flags      Flags
 *
 *  \retval cnt       Number of matches
 */
uint32_t DetectTlsSniInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                SSLState *ssl_state, uint8_t flags)
{
    SCEnter();

    uint8_t *buffer;
    uint32_t buffer_len;
    uint32_t cnt = 0;

    if (ssl_state->client_connp.sni == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->client_connp.sni;
    buffer_len = strlen(ssl_state->client_connp.sni);

    cnt = TlsSniPatternSearch(det_ctx, buffer, buffer_len, flags);

    SCReturnUInt(cnt);
}

/** \brief Do the content inspection and validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect
 *  \param sm       SigMatch to inspect
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param state    App layer state
 *
 *  \retval 0       No match
 *  \retval 1       Match
 */
int DetectEngineInspectTlsSni(ThreadVars *tv, DetectEngineCtx *de_ctx,
                              DetectEngineThreadCtx *det_ctx, Signature *s,
                              Flow *f, uint8_t flags, void *alstate, void *txv,
                              uint64_t tx_id)
{
    uint8_t *buffer;
    uint16_t buffer_len;
    int cnt = 0;

    SSLState *ssl_state = (SSLState *)alstate;

    if (ssl_state->client_connp.sni == NULL)
        return 0;

    buffer = (uint8_t *)ssl_state->client_connp.sni;
    buffer_len = strlen(ssl_state->client_connp.sni);

    cnt = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_TLSSNI_MATCH],
            f, buffer, buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_TLSSNI, NULL);

    return cnt;
}
