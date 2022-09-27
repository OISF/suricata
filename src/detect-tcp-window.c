/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements the window keyword.
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-tcp-window.h"

#include "util-byte.h"

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#endif
/**
 * \brief Regex for parsing our window option
 */
#define PARSE_REGEX  "^\\s*([!])?\\s*([0-9]{1,9}+)\\s*$"

static DetectParseRegex parse_regex;

static int DetectWindowMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectWindowSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectWindowRegisterTests(void);
#endif
void DetectWindowFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for window: keyword
 */
void DetectWindowRegister (void)
{
    sigmatch_table[DETECT_WINDOW].name = "tcp.window";
    sigmatch_table[DETECT_WINDOW].alias = "window";
    sigmatch_table[DETECT_WINDOW].desc = "check for a specific TCP window size";
    sigmatch_table[DETECT_WINDOW].url = "/rules/header-keywords.html#window";
    sigmatch_table[DETECT_WINDOW].Match = DetectWindowMatch;
    sigmatch_table[DETECT_WINDOW].Setup = DetectWindowSetup;
    sigmatch_table[DETECT_WINDOW].Free  = DetectWindowFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_WINDOW].RegisterTests = DetectWindowRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to match the window size on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectWindowData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectWindowMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectWindowData *wd = (const DetectWindowData *)ctx;

    if ( !(PKT_IS_TCP(p)) || wd == NULL || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if ( (!wd->negated && wd->size == TCP_GET_WINDOW(p)) || (wd->negated && wd->size != TCP_GET_WINDOW(p))) {
        return 1;
    }

    return 0;
}

/**
 * \brief This function is used to parse window options passed via window: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param windowstr Pointer to the user provided window options (negation! and size)
 *
 * \retval wd pointer to DetectWindowData on success
 * \retval NULL on failure
 */
static DetectWindowData *DetectWindowParse(DetectEngineCtx *de_ctx, const char *windowstr)
{
    DetectWindowData *wd = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&parse_regex, windowstr, 0, 0);
    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, windowstr);
        goto error;
    }

    wd = SCMalloc(sizeof(DetectWindowData));
    if (unlikely(wd == NULL))
        goto error;

    if (ret > 1) {
        char copy_str[128] = "";
        pcre2len = sizeof(copy_str);
        res = SC_Pcre2SubstringCopy(parse_regex.match, 1, (PCRE2_UCHAR8 *)copy_str, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            goto error;
        }

        /* Detect if it's negated */
        if (copy_str[0] == '!')
            wd->negated = 1;
        else
            wd->negated = 0;

        if (ret > 2) {
            pcre2len = sizeof(copy_str);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, 2, (PCRE2_UCHAR8 *)copy_str, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                goto error;
            }

            /* Get the window size if it's a valid value (in packets, we
             * should alert if this doesn't happend from decode) */
            if (StringParseUint16(&wd->size, 10, 0, copy_str) < 0) {
                goto error;
            }
        }
    }

    return wd;

error:
    if (wd != NULL)
        DetectWindowFree(de_ctx, wd);
    return NULL;

}

/**
 * \brief this function is used to add the parsed window sizedata into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param windowstr pointer to the user provided window options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectWindowSetup (DetectEngineCtx *de_ctx, Signature *s, const char *windowstr)
{
    DetectWindowData *wd = NULL;
    SigMatch *sm = NULL;

    wd = DetectWindowParse(de_ctx, windowstr);
    if (wd == NULL) goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_WINDOW;
    sm->ctx = (SigMatchCtx *)wd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (wd != NULL) DetectWindowFree(de_ctx, wd);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectWindowData
 *
 * \param wd pointer to DetectWindowData
 */
void DetectWindowFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectWindowData *wd = (DetectWindowData *)ptr;
    SCFree(wd);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectWindowTestParse01 is a test to make sure that we set the size correctly
 *  when given valid window opt
 */
static int DetectWindowTestParse01 (void)
{
    int result = 0;
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "35402");
    if (wd != NULL &&wd->size==35402) {
        DetectWindowFree(NULL, wd);
        result = 1;
    }

    return result;
}

/**
 * \test DetectWindowTestParse02 is a test for setting the window opt negated
 */
static int DetectWindowTestParse02 (void)
{
    int result = 0;
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "!35402");
    if (wd != NULL) {
        if (wd->negated == 1 && wd->size==35402) {
            result = 1;
        } else {
            printf("expected wd->negated=1 and wd->size=35402\n");
        }
        DetectWindowFree(NULL, wd);
    }

    return result;
}

/**
 * \test DetectWindowTestParse03 is a test to check for an empty value
 */
static int DetectWindowTestParse03 (void)
{
    int result = 0;
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "");
    if (wd == NULL) {
        result = 1;
    } else {
        printf("expected a NULL pointer (It was an empty string)\n");
    }
    DetectWindowFree(NULL, wd);

    return result;
}

/**
 * \test DetectWindowTestParse03 is a test to check for a big value
 */
static int DetectWindowTestParse04 (void)
{
    int result = 0;
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "1235402");
    if (wd != NULL) {
        printf("expected a NULL pointer (It was exceeding the MAX window size)\n");
        DetectWindowFree(NULL, wd);
    }else
        result=1;

    return result;
}

/**
 * \test DetectWindowTestPacket01 is a test to check window with constructed packets
 */
static int DetectWindowTestPacket01 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    /* TCP wwindow = 40 */
    p[0]->tcph->th_win = htons(40);

    /* TCP window = 41 */
    p[1]->tcph->th_win = htons(41);

    const char *sigs[2];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing window 1\"; window:40; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing window 2\"; window:41; sid:2;)";

    uint32_t sid[2] = {1, 2};

    uint32_t results[3][2] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {1, 0},
                              /* packet 1 should not match */
                              {0, 1},
                              /* packet 2 should not match */
                              {0, 0} };
    result = UTHGenericTest(p, 3, sigs, sid, (uint32_t *) results, 2);

    UTHFreePackets(p, 3);
end:
    return result;
}

/**
 * \brief this function registers unit tests for DetectWindow
 */
void DetectWindowRegisterTests(void)
{
    UtRegisterTest("DetectWindowTestParse01", DetectWindowTestParse01);
    UtRegisterTest("DetectWindowTestParse02", DetectWindowTestParse02);
    UtRegisterTest("DetectWindowTestParse03", DetectWindowTestParse03);
    UtRegisterTest("DetectWindowTestParse04", DetectWindowTestParse04);
    UtRegisterTest("DetectWindowTestPacket01", DetectWindowTestPacket01);
}
#endif /* UNITTESTS */
