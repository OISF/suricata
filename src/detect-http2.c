/* Copyright (C) 2020 Open Information Security Foundation
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
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-http2.h"
#include "util-byte.h"
#include "rust.h"

/* prototypes */
static int DetectHTTP2frametypeMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2frametypeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2frametypeFree (void *);
#ifdef UNITTESTS
void DetectHTTP2RegisterTests (void);
#endif

static int g_http2_match_buffer_id = 0;

static int DetectEngineInspectHTTP2(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                   DetectEngineThreadCtx *det_ctx, const Signature *s, const SigMatchData *smd,
                                   Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

/**
 * \brief Registration function for HTTP2 keywords
 */

void DetectHttp2Register(void)
{
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].name = "http2.frametype";
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].desc = "match on HTTP2 frame type field";
    //TODO create a new doc file for HTTP2 keywords
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].url = DOC_URL DOC_VERSION "/rules/http2-keywords.html#frametype";
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Match = NULL;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].AppLayerTxMatch = DetectHTTP2frametypeMatch;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Setup = DetectHTTP2frametypeSetup;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Free = DetectHTTP2frametypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].RegisterTests = DetectHTTP2RegisterTests;
#endif
    //TODO investigate why this is needed
    DetectAppLayerInspectEngineRegister("http2",
                                        ALPROTO_HTTP2, SIG_FLAG_TOSERVER, 0,
                                        DetectEngineInspectHTTP2);
    DetectAppLayerInspectEngineRegister("http2",
                                        ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, 0,
                                        DetectEngineInspectHTTP2);

    g_http2_match_buffer_id = DetectBufferTypeRegister("http2");

    return;
}

/**
 * \brief This function is used to match HTTP2 frame type rule option on a transaction with those passed via http2.frametype:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2frametypeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    uint8_t *detect = (uint8_t *)ctx;

    int value = rs_http2_tx_get_frametype(txv, flags);
    if (value < 0) {
        //no value, no match
        return 0;
    }
    return *detect == value;
}

static int DetectHTTP2FuncParseFrameType(const char *str, uint8_t *ft)
{
    // first parse numeric value
    if (ByteExtractStringUint8(ft, 10, strlen(str), str) >= 0) {
        return 1;
    }

    // it it failed so far, parse string value from enumeration
    int r = rs_http2_parse_frametype(str);
    if (r >= 0) {
        *ft = r;
        return 1;
    }

    return 0;
}

/**
 * \brief this function is used to attach the parsed http2.frametype data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.frametype options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2frametypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    uint8_t frame_type;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    if (!DetectHTTP2FuncParseFrameType(str, &frame_type)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                   "Invalid argument \"%s\" supplied to http2.frametype keyword.", str);
        return -1;
    }

    //TODO do we need to allocate ? Could we unionize sm->ctx ?
    uint8_t *http2ft = SCCalloc(1, sizeof(uint8_t));
    if (http2ft == NULL)
        return -1;
    *http2ft = frame_type;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2frametypeFree(http2ft);
        return -1;
    }

    sm->type = DETECT_HTTP2_FRAMETYPE;
    sm->ctx = (SigMatchCtx *)http2ft;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with uint8_t
 *
 * \param ptr pointer to uint8_t
 */
void DetectHTTP2frametypeFree(void *ptr)
{
    SCFree(ptr);
}

#ifdef UNITTESTS
#include "tests/detect-http2.c"
#endif
