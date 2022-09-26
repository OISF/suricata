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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-tos.h"

#include "util-byte.h"

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#endif
#define PARSE_REGEX  "^\\s*(!?\\s*[0-9]{1,3}|!?\\s*[xX][0-9a-fA-F]{1,2})\\s*$"

static DetectParseRegex parse_regex;

static int DetectTosSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectTosMatch(DetectEngineThreadCtx *, Packet *,
                          const Signature *, const SigMatchCtx *);
#ifdef UNITTESTS
static void DetectTosRegisterTests(void);
#endif
static void DetectTosFree(DetectEngineCtx *, void *);

#define DETECT_IPTOS_MIN 0
#define DETECT_IPTOS_MAX 255

/**
 * \brief Register Tos keyword.
 */
void DetectTosRegister(void)
{
    sigmatch_table[DETECT_TOS].name = "tos";
    sigmatch_table[DETECT_TOS].desc = "match on specific decimal values of the IP header TOS field";
    sigmatch_table[DETECT_TOS].Match = DetectTosMatch;
    sigmatch_table[DETECT_TOS].Setup = DetectTosSetup;
    sigmatch_table[DETECT_TOS].Free = DetectTosFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TOS].RegisterTests = DetectTosRegisterTests;
#endif
    sigmatch_table[DETECT_TOS].flags =
        (SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_HANDLE_NEGATION);
    sigmatch_table[DETECT_TOS].url =
        "/rules/header-keywords.html#tos";

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief Match function for tos keyword.
 *
 * \param tv ThreadVars instance.
 * \param det_ctx Pointer to the detection thread ctx.
 * \param p Pointer to the packet.
 * \param m Pointer to the SigMatch containing the tos data.
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTosMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
                   const Signature *s, const SigMatchCtx *ctx)
{
    const DetectTosData *tosd = (const DetectTosData *)ctx;
    int result = 0;

    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if (tosd->tos == IPV4_GET_IPTOS(p)) {
        SCLogDebug("tos match found for %d\n", tosd->tos);
        result = 1;
    }

    return (tosd->negated ^ result);
}

static DetectTosData *DetectTosParse(const char *arg, bool negate)
{
    DetectTosData *tosd = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&parse_regex, arg, 0, 0);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tos option - %s. "
                   "The tos option value must be in the range "
                   "%u - %u", arg, DETECT_IPTOS_MIN, DETECT_IPTOS_MAX);
        goto error;
    }

    /* For TOS value */
    char tosbytes_str[64] = "";
    pcre2len = sizeof(tosbytes_str);
    res = pcre2_substring_copy_bynumber(
            parse_regex.match, 1, (PCRE2_UCHAR8 *)tosbytes_str, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }

    int64_t tos = 0;

    if (tosbytes_str[0] == 'x' || tosbytes_str[0] == 'X') {
        if (StringParseInt64(&tos, 16, 0, &tosbytes_str[1]) < 0) {
            goto error;
        }
    } else {
        if (StringParseInt64(&tos, 10, 0, &tosbytes_str[0]) < 0) {
            goto error;
        }
    }

    if (!(tos >= DETECT_IPTOS_MIN && tos <= DETECT_IPTOS_MAX)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid tos argument - "
                   "%s.  The tos option value must be in the range "
                   "%u - %u", tosbytes_str, DETECT_IPTOS_MIN, DETECT_IPTOS_MAX);
        goto error;
    }

    tosd = SCMalloc(sizeof(DetectTosData));
    if (unlikely(tosd == NULL))
        goto error;
    tosd->tos = (uint8_t)tos;
    tosd->negated = negate;

    return tosd;

error:
    return NULL;
}

/**
 * \brief Setup function for tos argument.  Parse the argument and
 *        add it into the sig.
 *
 * \param de_ctx Detection Engine Context instance.
 * \param s Pointer to the signature.
 * \param arg Argument to be parsed.
 *
 * \retval  0 on Success.
 * \retval -1 on Failure.
 */
static int DetectTosSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectTosData *tosd = DetectTosParse(arg, s->init_data->negated);
    if (tosd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTosFree(de_ctx, tosd);
        return -1;
    }

    sm->type = DETECT_TOS;
    sm->ctx = (SigMatchCtx *)tosd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/**
 * \brief Free data allocated by the tos keyword.
 *
 * \param tosd Data to be freed.
 */
static void DetectTosFree(DetectEngineCtx *de_ctx, void *tosd)
{
    SCFree(tosd);
}

/********************************Unittests***********************************/

#ifdef UNITTESTS

static int DetectTosTest01(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("12", false);
    if (tosd != NULL && tosd->tos == 12 && !tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest02(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("123", false);
    if (tosd != NULL && tosd->tos == 123 && !tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest04(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("256", false);
    if (tosd != NULL) {
        DetectTosFree(NULL, tosd);
        return 0;
    }

    return 1;
}

static int DetectTosTest05(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("boom", false);
    if (tosd != NULL) {
        DetectTosFree(NULL, tosd);
        return 0;
    }

    return 1;
}

static int DetectTosTest06(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("x12", false);
    if (tosd != NULL && tosd->tos == 0x12 && !tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest07(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("X12", false);
    if (tosd != NULL && tosd->tos == 0x12 && !tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest08(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("x121", false);
    if (tosd != NULL) {
        DetectTosFree(NULL, tosd);
        return 0;
    }

    return 1;
}

static int DetectTosTest09(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("12", true);
    if (tosd != NULL && tosd->tos == 12 && tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest10(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("x12", true);
    if (tosd != NULL && tosd->tos == 0x12 && tosd->negated) {
        DetectTosFree(NULL, tosd);
        return 1;
    }

    return 0;
}

static int DetectTosTest12(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    IPV4_SET_RAW_IPTOS(p->ip4h, 10);

    const char *sigs[4];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; tos: 10 ; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; tos: ! 10; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; tos:20 ; sid:3;)";
    sigs[3]= "alert ip any any -> any any (msg:\"Testing id 3\"; tos:! 20; sid:4;)";

    uint32_t sid[4] = {1, 2, 3, 4};

    uint32_t results[1][4] =
        {
            {1, 0, 0, 1},
        };

    result = UTHGenericTest(&p, 1, sigs, sid, (uint32_t *) results, 4);

    UTHFreePackets(&p, 1);

end:
    return result;
}

void DetectTosRegisterTests(void)
{
    UtRegisterTest("DetectTosTest01", DetectTosTest01);
    UtRegisterTest("DetectTosTest02", DetectTosTest02);
    UtRegisterTest("DetectTosTest04", DetectTosTest04);
    UtRegisterTest("DetectTosTest05", DetectTosTest05);
    UtRegisterTest("DetectTosTest06", DetectTosTest06);
    UtRegisterTest("DetectTosTest07", DetectTosTest07);
    UtRegisterTest("DetectTosTest08", DetectTosTest08);
    UtRegisterTest("DetectTosTest09", DetectTosTest09);
    UtRegisterTest("DetectTosTest10", DetectTosTest10);
    UtRegisterTest("DetectTosTest12", DetectTosTest12);
    return;
}
#endif
