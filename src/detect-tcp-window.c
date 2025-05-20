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
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-tcp-window.h"
#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

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

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!(PacketIsTCP(p)) || wd == NULL) {
        return 0;
    }

    const uint16_t window = TCP_GET_RAW_WINDOW(PacketGetTCP(p));
    if ((!wd->negated && wd->size == window) || (wd->negated && wd->size != window)) {
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
    int res = 0;
    size_t pcre2len;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, windowstr, 0, 0);
    if (ret < 1 || ret > 3) {
        SCLogError("pcre_exec parse error, ret %" PRId32 ", string %s", ret, windowstr);
        goto error;
    }

    wd = SCMalloc(sizeof(DetectWindowData));
    if (unlikely(wd == NULL))
        goto error;

    if (ret > 1) {
        char copy_str[128] = "";
        pcre2len = sizeof(copy_str);
        res = SC_Pcre2SubstringCopy(match, 1, (PCRE2_UCHAR8 *)copy_str, &pcre2len);
        if (res < 0) {
            SCLogError("pcre2_substring_copy_bynumber failed");
            goto error;
        }

        /* Detect if it's negated */
        if (copy_str[0] == '!')
            wd->negated = 1;
        else
            wd->negated = 0;

        if (ret > 2) {
            pcre2len = sizeof(copy_str);
            res = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)copy_str, &pcre2len);
            if (res < 0) {
                SCLogError("pcre2_substring_copy_bynumber failed");
                goto error;
            }

            /* Get the window size if it's a valid value (in packets, we
             * should alert if this doesn't happen from decode) */
            if (StringParseUint16(&wd->size, 10, 0, copy_str) < 0) {
                goto error;
            }
        }
    }

    pcre2_match_data_free(match);
    return wd;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
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

    wd = DetectWindowParse(de_ctx, windowstr);
    if (wd == NULL) goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_WINDOW, (SigMatchCtx *)wd, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (wd != NULL)
        DetectWindowFree(de_ctx, wd);
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
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "35402");
    FAIL_IF_NULL(wd);
    FAIL_IF_NOT(wd->size == 35402);

    DetectWindowFree(NULL, wd);
    PASS;
}

/**
 * \test DetectWindowTestParse02 is a test for setting the window opt negated
 */
static int DetectWindowTestParse02 (void)
{
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "!35402");
    FAIL_IF_NULL(wd);
    FAIL_IF_NOT(wd->negated == 1);
    FAIL_IF_NOT(wd->size == 35402);

    DetectWindowFree(NULL, wd);
    PASS;
}

/**
 * \test DetectWindowTestParse03 is a test to check for an empty value
 */
static int DetectWindowTestParse03 (void)
{
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "");
    FAIL_IF_NOT_NULL(wd);

    DetectWindowFree(NULL, wd);
    PASS;
}

/**
 * \test DetectWindowTestParse03 is a test to check for a big value
 */
static int DetectWindowTestParse04 (void)
{
    DetectWindowData *wd = NULL;
    wd = DetectWindowParse(NULL, "1235402");
    FAIL_IF_NOT_NULL(wd);

    DetectWindowFree(NULL, wd);
    PASS;
}

/**
 * \test DetectWindowTestPacket01 is a test to check window with constructed packets
 */
static int DetectWindowTestPacket01 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);

    FAIL_IF(p[0] == NULL || p[1] == NULL || p[2] == NULL);

    /* TCP wwindow = 40 */
    p[0]->l4.hdrs.tcph->th_win = htons(40);

    /* TCP window = 41 */
    p[1]->l4.hdrs.tcph->th_win = htons(41);

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
    FAIL_IF(UTHGenericTest(p, 3, sigs, sid, (uint32_t *)results, 2) == 0);

    UTHFreePackets(p, 3);
    PASS;
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
