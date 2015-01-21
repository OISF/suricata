/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#define DETECT_EVENTS

#include "detect-engine-event.h"
#include "util-unittest.h"

#define PARSE_REGEX "\\S[0-9A-z_]+[.][A-z0-9_+]+$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectEngineEventMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectEngineEventSetup (DetectEngineCtx *, Signature *, char *);
static int DetectDecodeEventSetup (DetectEngineCtx *, Signature *, char *);
static int DetectStreamEventSetup (DetectEngineCtx *, Signature *, char *);
static void DetectEngineEventFree (void *);
void EngineEventRegisterTests(void);


/**
 * \brief Registration function for decode-event: keyword
 */
void DetectEngineEventRegister (void)
{
    sigmatch_table[DETECT_ENGINE_EVENT].name = "engine-event";
    sigmatch_table[DETECT_ENGINE_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_ENGINE_EVENT].Setup = DetectEngineEventSetup;
    sigmatch_table[DETECT_ENGINE_EVENT].Free  = DetectEngineEventFree;
    sigmatch_table[DETECT_ENGINE_EVENT].RegisterTests = EngineEventRegisterTests;

    sigmatch_table[DETECT_DECODE_EVENT].name = "decode-event";
    sigmatch_table[DETECT_DECODE_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_DECODE_EVENT].Setup = DetectDecodeEventSetup;
    sigmatch_table[DETECT_DECODE_EVENT].Free  = DetectEngineEventFree;
    sigmatch_table[DETECT_DECODE_EVENT].flags |= SIGMATCH_DEONLY_COMPAT;

    sigmatch_table[DETECT_STREAM_EVENT].name = "stream-event";
    sigmatch_table[DETECT_STREAM_EVENT].Match = DetectEngineEventMatch;
    sigmatch_table[DETECT_STREAM_EVENT].Setup = DetectStreamEventSetup;
    sigmatch_table[DETECT_STREAM_EVENT].Free  = DetectEngineEventFree;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    return;

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
int DetectEngineEventMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
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
DetectEngineEventData *DetectEngineEventParse (char *rawstr)
{
    int i;
    DetectEngineEventData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0, found = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32
                ", string %s", ret, rawstr);
        goto error;
    }

    char copy_str[128] = "";
    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 0,
            copy_str, sizeof(copy_str));

    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
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
static int _DetectEngineEventSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr, int smtype)
{
    DetectEngineEventData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectEngineEventParse(rawstr);
    if (de == NULL)
        goto error;

    SCLogDebug("rawstr %s %u", rawstr, de->event);

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = smtype;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}


static int DetectEngineEventSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    return _DetectEngineEventSetup (de_ctx, s, rawstr, DETECT_ENGINE_EVENT);
}

/**
 * \brief this function will free memory associated with DetectEngineEventData
 *
 * \param de pointer to DetectEngineEventData
 */
static void DetectEngineEventFree(void *ptr)
{
    DetectEngineEventData *de = (DetectEngineEventData *)ptr;
    if (de)
        SCFree(de);
}


/**
 * \brief this function Setup the 'decode-event' keyword by setting the correct
 * signature type
*/
static int DetectDecodeEventSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    return _DetectEngineEventSetup(de_ctx, s, rawstr, DETECT_DECODE_EVENT);
}

/**
 * \brief this function Setup the 'stream-event' keyword by resolving the alias
*/
static int DetectStreamEventSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    char srawstr[MAX_SUBSTRINGS * 2] = "stream.";

    /* stream:$EVENT alias command develop as decode-event:stream.$EVENT */
    strlcat(srawstr, rawstr, 2 * MAX_SUBSTRINGS - strlen("stream.") - 1);

    return DetectEngineEventSetup(de_ctx, s, srawstr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS

/**
 * \test EngineEventTestParse01 is a test for a  valid decode-event value
 */
int EngineEventTestParse01 (void)
{
    DetectEngineEventData *de = NULL;
    de = DetectEngineEventParse("ipv4.pkt_too_small");
    if (de) {
        DetectEngineEventFree(de);
        return 1;
    }

    return 0;
}


/**
 * \test EngineEventTestParse02 is a test for a  valid upper + lower case decode-event value
 */
int EngineEventTestParse02 (void)
{
    DetectEngineEventData *de = NULL;
    de = DetectEngineEventParse("PPP.pkt_too_small");
    if (de) {
        DetectEngineEventFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test EngineEventTestParse03 is a test for a  valid upper case decode-event value
 */
int EngineEventTestParse03 (void)
{
    DetectEngineEventData *de = NULL;
    de = DetectEngineEventParse("IPV6.PKT_TOO_SMALL");
    if (de) {
        DetectEngineEventFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test EngineEventTestParse04 is a test for an  invalid upper case decode-event value
 */
int EngineEventTestParse04 (void)
{
    DetectEngineEventData *de = NULL;
    de = DetectEngineEventParse("IPV6.INVALID_EVENT");
    if (de) {
        DetectEngineEventFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test EngineEventTestParse05 is a test for an  invalid char into the decode-event value
 */
int EngineEventTestParse05 (void)
{
    DetectEngineEventData *de = NULL;
    de = DetectEngineEventParse("IPV-6,INVALID_CHAR");
    if (de) {
        DetectEngineEventFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test EngineEventTestParse06 is a test for match function with valid decode-event value
 */
int EngineEventTestParse06 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectEngineEventData *de = NULL;
    SigMatch *sm = NULL;


    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);

    ENGINE_SET_EVENT(p,PPP_PKT_TOO_SMALL);

    de = DetectEngineEventParse("ppp.pkt_too_small");
    if (de == NULL)
        goto error;

    de->event = PPP_PKT_TOO_SMALL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DECODE_EVENT;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectEngineEventMatch(&tv,NULL,p,NULL,sm->ctx);

    if(ret) {
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for EngineEvent
 */
void EngineEventRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("EngineEventTestParse01", EngineEventTestParse01, 1);
    UtRegisterTest("EngineEventTestParse02", EngineEventTestParse02, 1);
    UtRegisterTest("EngineEventTestParse03", EngineEventTestParse03, 1);
    UtRegisterTest("EngineEventTestParse04", EngineEventTestParse04, 0);
    UtRegisterTest("EngineEventTestParse05", EngineEventTestParse05, 0);
    UtRegisterTest("EngineEventTestParse06", EngineEventTestParse06, 1);
#endif /* UNITTESTS */
}
