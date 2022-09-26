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

#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-http2.h"
#include "util-byte.h"
#include "util-profiling.h"

#ifdef UNITTESTS
#endif
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
static int PrefilterMpmHttp2HeaderNameRegister(DetectEngineCtx *de_ctx,
                                               SigGroupHead *sgh, MpmCtx *mpm_ctx,
                                               const DetectBufferMpmRegistery *mpm_reg, int list_id);
static uint8_t DetectEngineInspectHttp2HeaderName(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

static int DetectHTTP2headerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg);
static int PrefilterMpmHttp2HeaderRegister(DetectEngineCtx *de_ctx,
                                               SigGroupHead *sgh, MpmCtx *mpm_ctx,
                                               const DetectBufferMpmRegistery *mpm_reg, int list_id);
static uint8_t DetectEngineInspectHttp2Header(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static bool DetectHttp2HeaderValidateCallback(const Signature *s, const char **sigerror);

#ifdef UNITTESTS
void DetectHTTP2RegisterTests (void);
#endif

static int g_http2_match_buffer_id = 0;
static int g_http2_header_name_buffer_id = 0;
static int g_http2_header_buffer_id = 0;


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
    sigmatch_table[DETECT_HTTP2_HEADERNAME].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2("http2_header_name", SIG_FLAG_TOCLIENT, 2,
                               PrefilterMpmHttp2HeaderNameRegister, NULL,
                               ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister2("http2_header_name",
                                         ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, HTTP2StateOpen,
                                         DetectEngineInspectHttp2HeaderName, NULL);
    DetectAppLayerMpmRegister2("http2_header_name", SIG_FLAG_TOSERVER, 2,
                               PrefilterMpmHttp2HeaderNameRegister, NULL,
                               ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister2("http2_header_name",
                                         ALPROTO_HTTP2, SIG_FLAG_TOSERVER, HTTP2StateOpen,
                                         DetectEngineInspectHttp2HeaderName, NULL);

    DetectBufferTypeSetDescriptionByName("http2_header_name",
                                         "HTTP2 header name");
    g_http2_header_name_buffer_id = DetectBufferTypeGetByName("http2_header_name");

    sigmatch_table[DETECT_HTTP2_HEADER].name = "http2.header";
    sigmatch_table[DETECT_HTTP2_HEADER].desc = "sticky buffer to match on one HTTP2 header name and value";
    sigmatch_table[DETECT_HTTP2_HEADER].url = "/rules/http2-keywords.html#header";
    sigmatch_table[DETECT_HTTP2_HEADER].Setup = DetectHTTP2headerSetup;
    sigmatch_table[DETECT_HTTP2_HEADER].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2("http2_header", SIG_FLAG_TOCLIENT, 2,
                               PrefilterMpmHttp2HeaderRegister, NULL,
                               ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister2("http2_header",
                                         ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, HTTP2StateOpen,
                                         DetectEngineInspectHttp2Header, NULL);
    DetectAppLayerMpmRegister2("http2_header", SIG_FLAG_TOSERVER, 2,
                               PrefilterMpmHttp2HeaderRegister, NULL,
                               ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister2("http2_header",
                                         ALPROTO_HTTP2, SIG_FLAG_TOSERVER, HTTP2StateOpen,
                                         DetectEngineInspectHttp2Header, NULL);

    DetectBufferTypeSetDescriptionByName("http2_header",
                                         "HTTP2 header name and value");
    DetectBufferTypeRegisterValidateCallback("http2_header", DetectHttp2HeaderValidateCallback);
    g_http2_header_buffer_id = DetectBufferTypeGetByName("http2_header");

    DetectAppLayerInspectEngineRegister2(
            "http2", ALPROTO_HTTP2, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2(
            "http2", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

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

    return rs_http2_tx_has_frametype(txv, flags, *detect);
}

static int DetectHTTP2FuncParseFrameType(const char *str, uint8_t *ft)
{
    // first parse numeric value
    if (ByteExtractStringUint8(ft, 10, (uint16_t)strlen(str), str) >= 0) {
        return 1;
    }

    // it it failed so far, parse string value from enumeration
    int r = rs_http2_parse_frametype(str);
    if (r >= 0 && r <= UINT8_MAX) {
        *ft = (uint8_t)r;
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

    uint8_t *http2ft = SCCalloc(1, sizeof(uint8_t));
    if (http2ft == NULL)
        return -1;
    *http2ft = frame_type;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2frametypeFree(NULL, http2ft);
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
void DetectHTTP2frametypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
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
    uint32_t *detect = (uint32_t *)ctx;

    return rs_http2_tx_has_errorcode(txv, flags, *detect);
    //TODOask handle negation rules
}

static int DetectHTTP2FuncParseErrorCode(const char *str, uint32_t *ec)
{
    // first parse numeric value
    if (ByteExtractStringUint32(ec, 10, (uint16_t)strlen(str), str) >= 0) {
        return 1;
    }

    // it it failed so far, parse string value from enumeration
    int r = rs_http2_parse_errorcode(str);
    if (r >= 0) {
        *ec = r;
        return 1;
    }

    return 0;
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
    uint32_t error_code;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    if (!DetectHTTP2FuncParseErrorCode(str, &error_code)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                   "Invalid argument \"%s\" supplied to http2.errorcode keyword.", str);
        return -1;
    }

    uint32_t *http2ec = SCCalloc(1, sizeof(uint32_t));
    if (http2ec == NULL)
        return -1;
    *http2ec = error_code;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2errorcodeFree(NULL, http2ec);
        return -1;
    }

    sm->type = DETECT_HTTP2_ERRORCODE;
    sm->ctx = (SigMatchCtx *)http2ec;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to uint32_t
 */
void DetectHTTP2errorcodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
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
    uint32_t nb = 0;
    int value = rs_http2_tx_get_next_priority(txv, flags, nb);
    const DetectU8Data *du8 = (const DetectU8Data *)ctx;
    while (value >= 0) {
        if (DetectU8Match((uint8_t)value, du8)) {
            return 1;
        }
        nb++;
        value = rs_http2_tx_get_next_priority(txv, flags, nb);
    }
    return 0;
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
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    DetectU8Data *prio = DetectU8Parse(str);
    if (prio == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        rs_detect_u8_free(prio);
        return -1;
    }

    sm->type = DETECT_HTTP2_PRIORITY;
    sm->ctx = (SigMatchCtx *)prio;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2priorityFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u8_free(ptr);
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
    uint32_t nb = 0;
    int value = rs_http2_tx_get_next_window(txv, flags, nb);
    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    while (value >= 0) {
        if (DetectU32Match(value, du32)) {
            return 1;
        }
        nb++;
        value = rs_http2_tx_get_next_window(txv, flags, nb);
    }
    return 0;
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
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    DetectU32Data *wu = DetectU32Parse(str);
    if (wu == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        rs_detect_u32_free(wu);
        return -1;
    }

    sm->type = DETECT_HTTP2_WINDOW;
    sm->ctx = (SigMatchCtx *)wu;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2windowFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
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
    return rs_http2_detect_sizeupdatectx_match(ctx, txv, flags);
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
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *su = rs_detect_u64_parse(str);
    if (su == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2settingsFree(NULL, su);
        return -1;
    }

    sm->type = DETECT_HTTP2_SIZEUPDATE;
    sm->ctx = (SigMatchCtx *)su;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with uint32_t
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectHTTP2sizeUpdateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
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
    return rs_http2_detect_settingsctx_match(ctx, txv, flags);
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
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    void *http2set = rs_http2_detect_settingsctx_parse(str);
    if (http2set == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2settingsFree(NULL, http2set);
        return -1;
    }

    sm->type = DETECT_HTTP2_SETTINGS;
    sm->ctx = (SigMatchCtx *)http2set;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with rust signature context
 *
 * \param ptr pointer to rust signature context
 */
void DetectHTTP2settingsFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_http2_detect_settingsctx_free(ptr);
}

static int DetectHTTP2headerNameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_http2_header_name_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    return 0;
}

static void PrefilterMpmHttp2HNameFree(void *ptr)
{
    SCFree(ptr);
}

static InspectionBuffer *GetHttp2HNameData(DetectEngineThreadCtx *det_ctx,
        const uint8_t flags, const DetectEngineTransforms *transforms,
        Flow *_f, const struct MpmListIdDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_http2_tx_get_header_name(cbdata->txv, flags, cbdata->local_id, &b, &b_len) != 1)
        return NULL;
    if (b == NULL || b_len == 0)
        return NULL;

    InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
    InspectionBufferApplyTransforms(buffer, transforms);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static void PrefilterTxHttp2HName(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;

    while(1) {
        // loop until we get a NULL

        struct MpmListIdDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = GetHttp2HNameData(det_ctx, flags, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static int PrefilterMpmHttp2HeaderNameRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    //TODOask use PrefilterMpmListId elsewhere
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttp2HName,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmHttp2HNameFree, mpm_reg->name);
}

static uint8_t DetectEngineInspectHttp2HeaderName(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        //TODOask use MpmListIdDataArgs elsewhere
        struct MpmListIdDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = GetHttp2HNameData(det_ctx, flags,
                transforms, f, &cbdata, engine->sm_list, false);

        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectHTTP2headerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_http2_header_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP2) != 0)
        return -1;

    return 0;
}

static void PrefilterMpmHttp2HeaderFree(void *ptr)
{
    SCFree(ptr);
}

static InspectionBuffer *GetHttp2HeaderData(DetectEngineThreadCtx *det_ctx,
        const uint8_t flags, const DetectEngineTransforms *transforms,
        Flow *_f, const struct MpmListIdDataArgs *cbdata,
        int list_id, bool first)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_http2_tx_get_header(cbdata->txv, flags, cbdata->local_id, &b, &b_len) != 1)
        return NULL;
    if (b == NULL || b_len == 0)
        return NULL;

    InspectionBufferSetupMulti(buffer, transforms, b, b_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static void PrefilterTxHttp2Header(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;

    while(1) {
        // loop until we get a NULL

        struct MpmListIdDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer = GetHttp2HeaderData(det_ctx, flags, ctx->transforms,
                f, &cbdata, list_id, true);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                    &det_ctx->mtcu, &det_ctx->pmq,
                    buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static int PrefilterMpmHttp2HeaderRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttp2Header,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress,
            pectx, PrefilterMpmHttp2HeaderFree, mpm_reg->name);
}

static uint8_t DetectEngineInspectHttp2Header(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct MpmListIdDataArgs cbdata = { local_id, txv, };
        InspectionBuffer *buffer = GetHttp2HeaderData(det_ctx, flags,
                transforms, f, &cbdata, engine->sm_list, false);

        if (buffer == NULL || buffer->inspect == NULL)
            break;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              NULL, f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset, DETECT_CI_FLAGS_SINGLE,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static bool DetectHttp2HeaderValidateCallback(const Signature *s, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_http2_header_buffer_id];
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_CONTENT)
            continue;
        const DetectContentData *cd = (DetectContentData *)sm->ctx;
        bool escaped = false;
        bool namevaluesep = false;
        for (size_t i = 0; i < cd->content_len; ++i) {
            if (escaped) {
                if (cd->content[i] == ' ') {
                    if (namevaluesep) {
                        *sigerror = "Invalid http2.header string : "
                        "': ' is a special sequence for separation between name and value "
                        " and thus can only be present once";
                        SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
                        return false;
                    }
                    namevaluesep = true;
                } else if (cd->content[i] != ':') {
                    *sigerror = "Invalid http2.header string : "
                                "':' is an escaping character for itself, "
                                "or space for the separation between name and value";
                    SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
                    return false;
                }
                escaped = false;
            } else if(cd->content[i] == ':') {
                escaped = true;
            }
        }
        if (escaped) {
            *sigerror = "Invalid http2.header string : "
            "':' is an escaping character for itself, "
            "or space for the separation between name and value";
            SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
            return false;
        }
    }
    return true;
}

#ifdef UNITTESTS
#include "tests/detect-http2.c"
#endif
