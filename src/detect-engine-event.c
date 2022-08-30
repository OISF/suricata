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

/**
 * \file
 *
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements the decode-event keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "decode-events.h"

#include "util-debug.h"

#include "stream-tcp.h"


/* Need to get the DEvents[] array */

#include "detect-engine-event.h"
#include "util-unittest.h"

#define PARSE_REGEX "\\S[0-9A-z_]+[.][A-z0-9_+.]+$"

static DetectParseRegex parse_regex;

static int DetectEngineEventMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectEngineEventSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectDecodeEventSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectStreamEventSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectEngineEventFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void EngineEventRegisterTests(void);
#endif

/**
 * \brief Registration function for decode-event: keyword
 */
void DetectEngineEventRegister (void)
{
    sigmatch_table[DETECT_ENGINE_EVENT].name = "engine-event";
    sigmatch_table[DETECT_ENGINE_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_ENGINE_EVENT].Setup = DetectEngineEventSetup;
    sigmatch_table[DETECT_ENGINE_EVENT].Free  = DetectEngineEventFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ENGINE_EVENT].RegisterTests = EngineEventRegisterTests;
#endif

    sigmatch_table[DETECT_DECODE_EVENT].name = "decode-event";
    sigmatch_table[DETECT_DECODE_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_DECODE_EVENT].Setup = DetectDecodeEventSetup;
    sigmatch_table[DETECT_DECODE_EVENT].Free  = DetectEngineEventFree;
    sigmatch_table[DETECT_DECODE_EVENT].flags |= SIGMATCH_DEONLY_COMPAT;

    sigmatch_table[DETECT_STREAM_EVENT].name = "stream-event";
    sigmatch_table[DETECT_STREAM_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_STREAM_EVENT].Setup = DetectStreamEventSetup;
    sigmatch_table[DETECT_STREAM_EVENT].Free  = DetectEngineEventFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match decoder event flags set on a packet with those passed via decode-event:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the Signature
 * \param m pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEngineEventMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectEngineEventData *de = (const DetectEngineEventData *)ctx;

    if (ENGINE_ISSET_EVENT(p, de->event)) {
        SCLogDebug("de->event matched %u", de->event);
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

/**
 * \brief This function is used to parse decoder events options passed via decode-event: keyword
 *
 * \param rawstr Pointer to the user provided decode-event options
 *
 * \retval de pointer to DetectFlowData on success
 * \retval NULL on failure
 */
static DetectEngineEventData *DetectEngineEventParse (const char *rawstr)
{
    int i;
    DetectEngineEventData *de = NULL;
    int ret = 0, res = 0, found = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32
                ", string %s", ret, rawstr);
        goto error;
    }

    char copy_str[128] = "";
    pcre2len = sizeof(copy_str);
    res = pcre2_substring_copy_bynumber(parse_regex.match, 0, (PCRE2_UCHAR8 *)copy_str, &pcre2len);

    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    for (i = 0; DEvents[i].event_name != NULL; i++) {
        if (strcasecmp(DEvents[i].event_name,copy_str) == 0) {
            found = 1;
            break;
        }
    }

    if (found == 0) {
        SCLogError(SC_ERR_UNKNOWN_DECODE_EVENT, "unknown decode event \"%s\"",
                copy_str);
        goto error;
    }

    de = SCMalloc(sizeof(DetectEngineEventData));
    if (unlikely(de == NULL))
        goto error;

    de->event = DEvents[i].code;

    if (de->event == STREAM_REASSEMBLY_OVERLAP_DIFFERENT_DATA) {
        StreamTcpReassembleConfigEnableOverlapCheck();
    }
    return de;

error:
    if (de)
        SCFree(de);
    return NULL;
}

/**
 * \brief this function is used to add the parsed decode-event into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided decode-event options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEngineEventSetupDo(
        DetectEngineCtx *de_ctx, Signature *s, const char *rawstr, uint16_t smtype)
{
    DetectEngineEventData *de = DetectEngineEventParse(rawstr);
    if (de == NULL)
        return -1;

    SCLogDebug("rawstr %s %u", rawstr, de->event);

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        SCFree(de);
        return -1;
    }

    sm->type = smtype;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;
}


static int DetectEngineEventSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    return DetectEngineEventSetupDo (de_ctx, s, rawstr, DETECT_ENGINE_EVENT);
}

/**
 * \brief this function will free memory associated with DetectEngineEventData
 *
 * \param de pointer to DetectEngineEventData
 */
static void DetectEngineEventFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectEngineEventData *de = (DetectEngineEventData *)ptr;
    if (de)
        SCFree(de);
}


/**
 * \brief this function Setup the 'decode-event' keyword by setting the correct
 * signature type
*/
static int DetectDecodeEventSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    char drawstr[64] = "decoder.";

    /* decoder:$EVENT alias command develop as decode-event:decoder.$EVENT */
    strlcat(drawstr, rawstr, sizeof(drawstr));

    return DetectEngineEventSetupDo(de_ctx, s, drawstr, DETECT_DECODE_EVENT);
}

/**
 * \brief this function Setup the 'stream-event' keyword by resolving the alias
*/
static int DetectStreamEventSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    char srawstr[64] = "stream.";

    if (strcmp(rawstr, "est_synack_resend_with_different_ack") == 0) {
        rawstr = "est_synack_resend_with_diff_ack";
    } else if (strcmp(rawstr, "3whs_synack_resend_with_different_ack") == 0) {
        rawstr = "3whs_synack_resend_with_diff_ack";
    }

    /* stream:$EVENT alias command develop as decode-event:stream.$EVENT */
    strlcat(srawstr, rawstr, sizeof(srawstr));

    return DetectEngineEventSetup(de_ctx, s, srawstr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS

/**
 * \test EngineEventTestParse01 is a test for a  valid decode-event value
 */
static int EngineEventTestParse01 (void)
{
    DetectEngineEventData *de = DetectEngineEventParse("decoder.ipv4.pkt_too_small");

    FAIL_IF_NULL(de);

    DetectEngineEventFree(NULL, de);

    PASS;
}


/**
 * \test EngineEventTestParse02 is a test for a  valid upper + lower case decode-event value
 */
static int EngineEventTestParse02 (void)
{
    DetectEngineEventData *de = DetectEngineEventParse("decoder.PPP.pkt_too_small");

    FAIL_IF_NULL(de);

    DetectEngineEventFree(NULL, de);

    PASS;
}

/**
 * \test EngineEventTestParse03 is a test for a  valid upper case decode-event value
 */
static int EngineEventTestParse03 (void)
{
    DetectEngineEventData *de = DetectEngineEventParse("decoder.IPV6.PKT_TOO_SMALL");

    FAIL_IF_NULL(de);

    DetectEngineEventFree(NULL, de);

    PASS;
}

/**
 * \test EngineEventTestParse04 is a test for an  invalid upper case decode-event value
 */
static int EngineEventTestParse04 (void)
{
    DetectEngineEventData *de = DetectEngineEventParse("decoder.IPV6.INVALID_EVENT");

    FAIL_IF_NOT_NULL(de);

    DetectEngineEventFree(NULL, de);

    PASS;
}

/**
 * \test EngineEventTestParse05 is a test for an  invalid char into the decode-event value
 */
static int EngineEventTestParse05 (void)
{
    DetectEngineEventData *de = DetectEngineEventParse("decoder.IPV-6,INVALID_CHAR");

    FAIL_IF_NOT_NULL(de);

    DetectEngineEventFree(NULL, de);

    PASS;
}

/**
 * \test EngineEventTestParse06 is a test for match function with valid decode-event value
 */
static int EngineEventTestParse06 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;

    memset(&tv, 0, sizeof(ThreadVars));

    ENGINE_SET_EVENT(p,PPP_PKT_TOO_SMALL);

    DetectEngineEventData *de = DetectEngineEventParse("decoder.ppp.pkt_too_small");
    FAIL_IF_NULL(de);

    de->event = PPP_PKT_TOO_SMALL;

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);

    sm->type = DETECT_DECODE_EVENT;
    sm->ctx = (SigMatchCtx *)de;

    FAIL_IF_NOT(DetectEngineEventMatch(NULL, p, NULL, sm->ctx));

    SCFree(p);
    SCFree(de);
    SCFree(sm);

    PASS;
}

/**
 * \brief this function registers unit tests for EngineEvent
 */
void EngineEventRegisterTests(void)
{
    UtRegisterTest("EngineEventTestParse01", EngineEventTestParse01);
    UtRegisterTest("EngineEventTestParse02", EngineEventTestParse02);
    UtRegisterTest("EngineEventTestParse03", EngineEventTestParse03);
    UtRegisterTest("EngineEventTestParse04", EngineEventTestParse04);
    UtRegisterTest("EngineEventTestParse05", EngineEventTestParse05);
    UtRegisterTest("EngineEventTestParse06", EngineEventTestParse06);
}
#endif /* UNITTESTS */
