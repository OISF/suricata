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
#include "detect-engine-uint.h"

#include "detect-http2.h"
#include "util-byte.h"
#include "rust.h"

#ifdef UNITTESTS
void DetectHTTP2frameTypeRegisterTests (void);
void DetectHTTP2errorCodeRegisterTests (void);
void DetectHTTP2priorityRegisterTests (void);
void DetectHTTP2windowRegisterTests (void);
void DetectHTTP2settingsRegisterTests (void);
#endif

/* prototypes */
static int DetectHTTP2frametypeMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2frametypeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2frametypeFree (void *);

static int DetectHTTP2errorcodeMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2errorcodeSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2errorcodeFree (void *);

static int DetectHTTP2priorityMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2prioritySetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2priorityFree (void *);

static int DetectHTTP2windowMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2windowSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2windowFree (void *);

static int DetectHTTP2settingsMatch(DetectEngineThreadCtx *det_ctx,
                                     Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                                     const SigMatchCtx *ctx);
static int DetectHTTP2settingsSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHTTP2settingsFree (void *);

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
    sigmatch_table[DETECT_HTTP2_FRAMETYPE].RegisterTests = DetectHTTP2frameTypeRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_ERRORCODE].name = "http2.errorcode";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].desc = "match on HTTP2 error code field";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].url = DOC_URL DOC_VERSION "/rules/http2-keywords.html#errorcode";
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Match = NULL;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].AppLayerTxMatch = DetectHTTP2errorcodeMatch;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Setup = DetectHTTP2errorcodeSetup;
    sigmatch_table[DETECT_HTTP2_ERRORCODE].Free = DetectHTTP2errorcodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_ERRORCODE].RegisterTests = DetectHTTP2errorCodeRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_PRIORITY].name = "http2.priority";
    sigmatch_table[DETECT_HTTP2_PRIORITY].desc = "match on HTTP2 priority weight field";
    sigmatch_table[DETECT_HTTP2_PRIORITY].url = DOC_URL DOC_VERSION "/rules/http2-keywords.html#priority";
    sigmatch_table[DETECT_HTTP2_PRIORITY].Match = NULL;
    sigmatch_table[DETECT_HTTP2_PRIORITY].AppLayerTxMatch = DetectHTTP2priorityMatch;
    sigmatch_table[DETECT_HTTP2_PRIORITY].Setup = DetectHTTP2prioritySetup;
    sigmatch_table[DETECT_HTTP2_PRIORITY].Free = DetectHTTP2priorityFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_PRIORITY].RegisterTests = DetectHTTP2priorityRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_WINDOW].name = "http2.window";
    sigmatch_table[DETECT_HTTP2_WINDOW].desc = "match on HTTP2 window update size increment field";
    sigmatch_table[DETECT_HTTP2_WINDOW].url = DOC_URL DOC_VERSION "/rules/http2-keywords.html#window";
    sigmatch_table[DETECT_HTTP2_WINDOW].Match = NULL;
    sigmatch_table[DETECT_HTTP2_WINDOW].AppLayerTxMatch = DetectHTTP2windowMatch;
    sigmatch_table[DETECT_HTTP2_WINDOW].Setup = DetectHTTP2windowSetup;
    sigmatch_table[DETECT_HTTP2_WINDOW].Free = DetectHTTP2windowFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_WINDOW].RegisterTests = DetectHTTP2windowRegisterTests;
#endif

    sigmatch_table[DETECT_HTTP2_SETTINGS].name = "http2.settings";
    sigmatch_table[DETECT_HTTP2_SETTINGS].desc = "match on HTTP2 settings identifier and value fields";
    sigmatch_table[DETECT_HTTP2_SETTINGS].url = DOC_URL DOC_VERSION "/rules/http2-keywords.html#settings";
    sigmatch_table[DETECT_HTTP2_SETTINGS].Match = NULL;
    sigmatch_table[DETECT_HTTP2_SETTINGS].AppLayerTxMatch = DetectHTTP2settingsMatch;
    sigmatch_table[DETECT_HTTP2_SETTINGS].Setup = DetectHTTP2settingsSetup;
    sigmatch_table[DETECT_HTTP2_SETTINGS].Free = DetectHTTP2settingsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP2_SETTINGS].RegisterTests = DetectHTTP2settingsRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister("http2",
                                        ALPROTO_HTTP2, SIG_FLAG_TOSERVER, 0,
                                        DetectEngineInspectHTTP2);
    DetectAppLayerInspectEngineRegister("http2",
                                        ALPROTO_HTTP2, SIG_FLAG_TOCLIENT, 0,
                                        DetectEngineInspectHTTP2);

    g_http2_match_buffer_id = DetectBufferTypeRegister("http2");
    DetectUintRegister();

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

    int value = rs_http2_tx_get_errorcode(txv, flags);
    if (value < 0) {
        //no value, no match
        return 0;
    }
    //TODO handle negation rules
    return *detect == (uint32_t) value;
}

static int DetectHTTP2FuncParseErrorCode(const char *str, uint32_t *ec)
{
    // first parse numeric value
    if (ByteExtractStringUint32(ec, 10, strlen(str), str) >= 0) {
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
        DetectHTTP2errorcodeFree(http2ec);
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
void DetectHTTP2errorcodeFree(void *ptr)
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
    int value = rs_http2_tx_get_priority(txv, flags);
    if (value < 0) {
        //no value, no match
        return 0;
    }

    const DetectU8Data *du8 = (const DetectU8Data *)ctx;
    return DetectU8Match(value, du8);
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
        SCFree(prio);
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
void DetectHTTP2priorityFree(void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief This function is used to match HTTP2 error code rule option on a transaction with those passed via http2.window:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectHTTP2windowMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    int value = rs_http2_tx_get_window(txv, flags);
    if (value < 0) {
        //no value, no match
        return 0;
    }

    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(value, du32);
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
        SCFree(wu);
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
void DetectHTTP2windowFree(void *ptr)
{
    SCFree(ptr);
}

typedef struct DetectHTTP2settingsSigCtx_ {
    uint16_t id;   /**identifier*/
    DetectU32Data *value; /** optional value*/
} DetectHTTP2settingsSigCtx;

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
    int id = rs_http2_tx_get_settingsid(txv, flags);
    if (id < 0) {
        //no settings, no match
        return 0;
    }

    const DetectHTTP2settingsSigCtx *setctx = (const DetectHTTP2settingsSigCtx *)ctx;
    if (setctx->id != id) {
        return 0;
    } else if (setctx->value == NULL) {
        //no value to match
        return 1;
    } else {
        int value = rs_http2_tx_get_settingsvalue(txv, flags);
        if (value < 0) {
            return 0;
        }
        return DetectU32Match(value, setctx->value);
    }
}

static int DetectHTTP2FuncParseSettingsId(const char *str, uint16_t *id)
{
    // first parse numeric value
    if (ByteExtractStringUint16(id, 10, strlen(str), str) >= 0) {
        return 1;
    }

    // it it failed so far, parse string value from enumeration
    int r = rs_http2_parse_settingsid(str);
    if (r >= 0) {
        *id = r;
        return 1;
    }

    return 0;
}

#define HTTP2_MAX_SETTINGS_ID_LEN 64

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

    const char * space = strchr(str, ' ');

    DetectHTTP2settingsSigCtx *http2set = SCCalloc(1, sizeof(DetectHTTP2settingsSigCtx));
    if (http2set == NULL)
        return -1;

    if (space) {
        // a space separates identifier and value

        // copy and isolate first part of string
        char str_first[HTTP2_MAX_SETTINGS_ID_LEN];
        if (HTTP2_MAX_SETTINGS_ID_LEN <= space - str) {
            SCFree(http2set);
            return -1;
        }
        strlcpy(str_first, str, space - str + 1);
        //TODO better no copy, and pass a length argument next ?

        if (!DetectHTTP2FuncParseSettingsId(str_first, &http2set->id)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                       "Invalid first argument \"%s\" supplied to http2.settings keyword.", str_first);
            SCFree(http2set);
            return -1;
        }

        http2set->value = DetectU32Parse(space+1);
        if (http2set->value == NULL) {
            SCFree(http2set);
            return -1;
        }
    } else {
        // no space means only id with no value
        if (!DetectHTTP2FuncParseSettingsId(str, &http2set->id)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                       "Invalid argument \"%s\" supplied to http2.settings keyword.", str);
            SCFree(http2set);
            return -1;
        }
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectHTTP2settingsFree(http2set);
        return -1;
    }

    sm->type = DETECT_HTTP2_SETTINGS;
    sm->ctx = (SigMatchCtx *)http2set;

    SigMatchAppendSMToList(s, sm, g_http2_match_buffer_id);

    return 0;
}

/**
 * \brief this function will free memory associated with DetectHTTP2settingsSigCtx
 *
 * \param ptr pointer to DetectHTTP2settingsSigCtx
 */
void DetectHTTP2settingsFree(void *ptr)
{
    DetectHTTP2settingsSigCtx *http2set = (DetectHTTP2settingsSigCtx *) ptr;
    SCFree(http2set->value);
    SCFree(http2set);
}

#ifdef UNITTESTS
#include "tests/detect-http2.c"
#endif
