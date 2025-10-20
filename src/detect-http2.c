/* Copyright (C) 2020-2022 Open Information Security Foundation
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
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-uint.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-helper.h"

#include "detect-http2.h"
#include "util-byte.h"
#include "rust.h"
#include "util-profiling.h"

#ifdef UNITTESTS
void DetectHTTP2frameTypeRegisterTests (void);
void DetectHTTP2errorCodeRegisterTests (void);
void DetectHTTP2priorityRegisterTests (void);
void DetectHTTP2windowRegisterTests (void);
void DetectHTTP2settingsRegisterTests (void);
void DetectHTTP2sizeUpdateRegisterTests (void);
#endif

/* prototypes */
static int DetectHTTP2frametypeMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2frametypeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2frametypeFree (DetectEngineCtx *, void *);

static int DetectHTTP2errorcodeMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2errorcodeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2errorcodeFree (DetectEngineCtx *, void *);

static int DetectHTTP2priorityMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2prioritySetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2priorityFree (DetectEngineCtx *, void *);

static int DetectHTTP2windowMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2windowSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2windowFree (DetectEngineCtx *, void *);

static int DetectHTTP2sizeUpdateMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2sizeUpdateSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2sizeUpdateFree (DetectEngineCtx *, void *);

static int DetectHTTP2settingsMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2settingsSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2settingsFree (DetectEngineCtx *, void *);

static int DetectHTTP2headerNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg);

#ifdef UNITTESTS
void DetectHTTP2RegisterTests (void);
#endif

static int g_http2_match_buffer_id = 0;
static int g_http2_complete_buffer_id = 0;
static int g_http2_header_name_buffer_id = 0;

/**
 * \brief Registration function for HTTP2 keywords
 */

void DetectHttp2Register(void)
{
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].name = "http2.frametype";
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].desc = "match on HTTP2 frame type field";
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].url = "/rules/http2-keywords.html#frametype";
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Match = NULL;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].AppLayerTxMatch = DetectHTTP2frametypeMatch;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Setup = DetectHTTP2frametypeSetup;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].Free = DetectHTTP2frametypeFree;
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].flags =
            SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].RegisterTests = DetectHTTP2frameTypeRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_ERRORCODE].name = "http2.errorcode";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].desc = "match on HTTP2 error code field";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].url = "/rules/http2-keywords.html#errorcode";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Match = NULL;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].AppLayerTxMatch = DetectHTTP2errorcodeMatch;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Setup = DetectHTTP2errorcodeSetup;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Free = DetectHTTP2errorcodeFree;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].flags =
            SIGMATCH_INFO_UINT32 | SIGMATCH_INFO_MULTI_UINT | SIGMATCH_INFO_ENUM_UINT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_ERRORCODE].RegisterTests = DetectHTTP2errorCodeRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_PRIORITY].name = "http2.priority";
    sigmatch_table[DETECT_HTTP2_PRIORITY].desc = "match on HTTP2 priority weight field";
    sigmatch_table[DETECT_HTTP2_PRIORITY].url = "/rules/http2-keywords.html#priority";
    sigmatch_table[DETECT_HTTP2_PRIORITY].Match = NULL;
    sigmatch_table[DETECT_HTTP2_PRIORITY].AppLayerTxMatch = DetectHTTP2priorityMatch;
    sigmatch_table[DETECT_HTTP2_PRIORITY].Setup = DetectHTTP2prioritySetup;
    sigmatch_table[DETECT_HTTP2_PRIORITY].Free = DetectHTTP2priorityFree;
    sigmatch_table[DETECT_HTTP2_PRIORITY].flags = SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_MULTI_UINT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_PRIORITY].RegisterTests = DetectHTTP2priorityRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_WINDOW].name = "http2.window";
    sigmatch_table[DETECT_HTTP2_WINDOW].desc = "match on HTTP2 window update size increment field";
    sigmatch_table[DETECT_HTTP2_WINDOW].url = "/rules/http2-keywords.html#window";
    sigmatch_table[DETECT_HTTP2_WINDOW].Match = NULL;
    sigmatch_table[DETECT_HTTP2_WINDOW].AppLayerTxMatch = DetectHTTP2windowMatch;
    sigmatch_table[DETECT_HTTP2_WINDOW].Setup = DetectHTTP2windowSetup;
    sigmatch_table[DETECT_HTTP2_WINDOW].Free = DetectHTTP2windowFree;
    sigmatch_table[DETECT_HTTP2_WINDOW].flags = SIGMATCH_INFO_UINT32 | SIGMATCH_INFO_MULTI_UINT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_WINDOW].RegisterTests = DetectHTTP2windowRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].name = "http2.size_update";
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].desc = "match on HTTP2 dynamic headers table size update";
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].url = "/rules/http2-keywords.html#sizeupdate";
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].Match = NULL;
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].AppLayerTxMatch = DetectHTTP2sizeUpdateMatch;
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].Setup = DetectHTTP2sizeUpdateSetup;
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].Free = DetectHTTP2sizeUpdateFree;
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].flags = SIGMATCH_INFO_UINT64;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_SIZEUPDATE].RegisterTests = DetectHTTP2sizeUpdateRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_SETTINGS].name = "http2.settings";
    sigmatch_table[DETECT_HTTP2_SETTINGS].desc = "match on HTTP2 settings identifier and value fields";
    sigmatch_table[DETECT_HTTP2_SETTINGS].url = "/rules/http2-keywords.html#settings";
    sigmatch_table[DETECT_HTTP2_SETTINGS].Match = NULL;
    sigmatch_table[DETECT_HTTP2_SETTINGS].AppLayerTxMatch = DetectHTTP2settingsMatch;
    sigmatch_table[DETECT_HTTP2_SETTINGS].Setup = DetectHTTP2settingsSetup;
    sigmatch_table[DETECT_HTTP2_SETTINGS].Free = DetectHTTP2settingsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_SETTINGS].RegisterTests = DetectHTTP2settingsRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_HEADERNAME].name = "http2.header_name";
    sigmatch_table[DETECT_HTTP2_HEADERNAME].desc = "sticky buffer to match on one HTTP2 header name";
    sigmatch_table[DETECT_HTTP2_HEADERNAME].url = "/rules/http2-keywords.html#header_name";
    sigmatch_table[DETECT_HTTP2_HEADERNAME].Setup = DetectHTTP2headerNameSetup;
    sigmatch_table[DETECT_HTTP2_HEADERNAME].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;

    DetectAppLayerMultiRegister("http2_header_name", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateOpen, SCHttp2TxGetHeaderName, 2);
    DetectAppLayerMultiRegister("http2_header_name", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateOpen, SCHttp2TxGetHeaderName, 2);

    DetectBufferTypeSupportsMultiInstance("http2_header_name");
    DetectBufferTypeSetDescriptionByName("http2_header_name",
                                         "HTTP2 header name");
    g_http2_header_name_buffer_id = DetectBufferTypeGetByName("http2_header_name");

    DetectAppLayerInspectEngineRegister(
            "http2", ALPROTO_HTTP2, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "http2", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_http2_match_buffer_id = DetectBufferTypeRegister("http2");

    DetectAppLayerInspectEngineRegister("http2_complete", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateClosed, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("http2_complete", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateClosed, DetectEngineInspectGenericList, NULL);

    g_http2_complete_buffer_id = DetectBufferTypeRegister("http2_complete");
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
    return SCHttp2TxHasFrametype(txv, flags, ctx);
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
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *dua8 = SCHttp2ParseFrametype(str);
    if (dua8 == NULL) {
        SCLogError("Invalid http2.frametype: %s", str);
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_FRAMETYPE, (SigMatchCtx *)dua8,
                g_http2_match_buffer_id) == NULL) {
        DetectHTTP2frametypeFree(NULL, dua8);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with uint8_t
 *
 * \param ptr pointer to uint8_t
 */
void DetectHTTP2frametypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8ArrayFree(ptr);
}

/**
 * \brief This function is used to match HTTP2 error code rule option on a transaction with those passed via http2.errorcode:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2errorcodeMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    return SCHttp2TxHasErrorCode(txv, flags, ctx);
}

/**
 * \brief this function is used to attach the parsed http2.errorcode data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.errorcode options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2errorcodeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *dua32 = SCHttp2ParseErrorCode(str);
    if (dua32 == NULL) {
        SCLogError("Invalid http2.errorcode: %s", str);
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_ERRORCODE, (SigMatchCtx *)dua32,
                g_http2_match_buffer_id) == NULL) {
        DetectHTTP2errorcodeFree(NULL, dua32);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to uint32_t
 */
void DetectHTTP2errorcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32ArrayFree(ptr);
}

/**
 * \brief This function is used to match HTTP2 error code rule option on a transaction with those passed via http2.priority:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2priorityMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    return SCHttp2PriorityMatch(txv, flags, ctx);
}

/**
 * \brief this function is used to attach the parsed http2.priority data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.priority options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2prioritySetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *prio = SCDetectU8ArrayParse(str);
    if (prio == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_PRIORITY, (SigMatchCtx *)prio,
                g_http2_match_buffer_id) == NULL) {
        DetectHTTP2priorityFree(NULL, prio);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2priorityFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8ArrayFree(ptr);
}

/**
 * \brief This function is used to match HTTP2 window rule option on a transaction with those passed via http2.window:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2windowMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    return SCHttp2WindowMatch(txv, flags, ctx);
}

/**
 * \brief this function is used to attach the parsed http2.window data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.window options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2windowSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *wu = SCDetectU32ArrayParse(str);
    if (wu == NULL)
        return -1;

    // use g_http2_complete_buffer_id as we may have window changes in any state
    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_WINDOW, (SigMatchCtx *)wu,
                g_http2_complete_buffer_id) == NULL) {
        DetectHTTP2windowFree(NULL, wu);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2windowFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32ArrayFree(ptr);
}

/**
 * \brief This function is used to match HTTP2 size update rule option on a transaction with those passed via http2.size_update:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2sizeUpdateMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    return SCHttp2DetectSizeUpdateCtxMatch(ctx, txv, flags);
}

/**
 * \brief this function is used to attach the parsed http2.size_update data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.size_update options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2sizeUpdateSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    DetectU64Data *su = SCDetectU64Parse(str);
    if (su == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_SIZEUPDATE, (SigMatchCtx *)su,
                g_http2_match_buffer_id) == NULL) {
        DetectHTTP2sizeUpdateFree(NULL, su);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2sizeUpdateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU64Free(ptr);
}

/**
 * \brief This function is used to match HTTP2 error code rule option on a transaction with those passed via http2.settings:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2settingsMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    return SCHttp2DetectSettingsCtxMatch(ctx, txv, flags);
}

/**
 * \brief this function is used to attach the parsed http2.settings data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided http2.settings options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHTTP2settingsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *http2set = SCHttp2DetectSettingsCtxParse(str);
    if (http2set == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_HTTP2_SETTINGS, (SigMatchCtx *)http2set,
                g_http2_match_buffer_id) == NULL) {
        DetectHTTP2settingsFree(NULL, http2set);
        return -1;
    }

    return 0;
}

/**
 * \brief this function will free memory associated with rust signature context
 *
 * \param ptr pointer to rust signature context
 */
void DetectHTTP2settingsFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCHttp2DetectSettingsCtxFree(ptr);
}

static int DetectHTTP2headerNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_http2_header_name_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS
#include "tests/detect-http2.c"
#endif
