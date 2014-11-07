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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-tos.h"

#include "app-layer-protos.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#define PARSE_REGEX  "^\\s*(!?\\s*[0-9]{1,3}|!?\\s*[xX][0-9a-fA-F]{1,2})\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectTosSetup(DetectEngineCtx *, Signature *, char *);
static int DetectTosMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                          Signature *, const SigMatchCtx *);
static void DetectTosRegisterTests(void);
static void DetectTosFree(void *);

#define DETECT_IPTOS_MIN 0
#define DETECT_IPTOS_MAX 255

/**
 * \brief Register Tos keyword.
 */
void DetectTosRegister(void)
{
    sigmatch_table[DETECT_TOS].name = "tos";
    sigmatch_table[DETECT_TOS].Match = DetectTosMatch;
    sigmatch_table[DETECT_TOS].Setup = DetectTosSetup;
    sigmatch_table[DETECT_TOS].Free = DetectTosFree;
    sigmatch_table[DETECT_TOS].RegisterTests = DetectTosRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at "
                   "offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    return;
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
int DetectTosMatch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p,
                   Signature *s, const SigMatchCtx *ctx)
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

DetectTosData *DetectTosParse(char *arg)
{
    DetectTosData *tosd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, arg, strlen(arg), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tos option - %s. "
                   "The tos option value must be in the range "
                   "%u - %u", arg, DETECT_IPTOS_MIN, DETECT_IPTOS_MAX);
        goto error;
    }

    const char *str_ptr;
    res = pcre_get_substring((char *)arg, ov, MAX_SUBSTRINGS, 1,
                             &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    int64_t tos = 0;
    int negated = 0;

    if (*str_ptr == '!') {
        str_ptr++;
        negated = 1;
    }

    while (isspace((unsigned char)*str_ptr))
        str_ptr++;

    if (*str_ptr == 'x' || *str_ptr == 'X') {
        int r = ByteExtractStringSigned(&tos, 16, 0, str_ptr + 1);
        if (r < 0) {
            goto error;
        }
    } else {
        int r = ByteExtractStringSigned(&tos, 10, 0, str_ptr);
        if (r < 0) {
            goto error;
        }
    }
    if (!(tos >= DETECT_IPTOS_MIN && tos <= DETECT_IPTOS_MAX)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid tos argument - "
                   "%s.  The tos option value must be in the range "
                   "%u - %u", str_ptr, DETECT_IPTOS_MIN, DETECT_IPTOS_MAX);
        goto error;
    }

    tosd = SCMalloc(sizeof(DetectTosData));
    if (unlikely(tosd == NULL))
        goto error;
    tosd->tos = (uint8_t)tos;
    tosd->negated = negated;

    return tosd;

error:
    if (tosd != NULL)
        DetectTosFree(tosd);
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
int DetectTosSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    DetectTosData *tosd;
    SigMatch *sm;

    tosd = DetectTosParse(arg);
    if (tosd == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TOS;
    sm->ctx = (SigMatchCtx *)tosd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    return -1;
}

/**
 * \brief Free data allocated by the tos keyword.
 *
 * \param tosd Data to be freed.
 */
void DetectTosFree(void *tosd)
{
    SCFree(tosd);
}

/********************************Unittests***********************************/

#ifdef UNITTESTS

int DetectTosTest01(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("12");
    if (tosd != NULL && tosd->tos == 12 && !tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest02(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("123");
    if (tosd != NULL && tosd->tos == 123 && !tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest03(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse(" 12 ");
    if (tosd != NULL && tosd->tos == 12 && !tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest04(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("256");
    if (tosd != NULL) {
        DetectTosFree(tosd);
        return 0;
    }

    return 1;
}

int DetectTosTest05(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("boom");
    if (tosd != NULL) {
        DetectTosFree(tosd);
        return 0;
    }

    return 1;
}

int DetectTosTest06(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("x12");
    if (tosd != NULL && tosd->tos == 0x12 && !tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest07(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("X12");
    if (tosd != NULL && tosd->tos == 0x12 && !tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest08(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("x121");
    if (tosd != NULL) {
        DetectTosFree(tosd);
        return 0;
    }

    return 1;
}

int DetectTosTest09(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("!12");
    if (tosd != NULL && tosd->tos == 12 && tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest10(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse("!x12");
    if (tosd != NULL && tosd->tos == 0x12 && tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest11(void)
{
    DetectTosData *tosd = NULL;
    tosd = DetectTosParse(" ! 12");
    if (tosd != NULL && tosd->tos == 12 && tosd->negated) {
        DetectTosFree(tosd);
        return 1;
    }

    return 0;
}

int DetectTosTest12(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    IPV4_SET_RAW_IPTOS(p->ip4h, 10);

    char *sigs[4];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; tos:10; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; tos:!10; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; tos:20; sid:3;)";
    sigs[3]= "alert ip any any -> any any (msg:\"Testing id 3\"; tos:!20; sid:4;)";

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

#endif

void DetectTosRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTosTest01", DetectTosTest01, 1);
    UtRegisterTest("DetectTosTest02", DetectTosTest02, 1);
    UtRegisterTest("DetectTosTest03", DetectTosTest03, 1);
    UtRegisterTest("DetectTosTest04", DetectTosTest04, 1);
    UtRegisterTest("DetectTosTest05", DetectTosTest05, 1);
    UtRegisterTest("DetectTosTest06", DetectTosTest06, 1);
    UtRegisterTest("DetectTosTest07", DetectTosTest07, 1);
    UtRegisterTest("DetectTosTest08", DetectTosTest08, 1);
    UtRegisterTest("DetectTosTest09", DetectTosTest09, 1);
    UtRegisterTest("DetectTosTest10", DetectTosTest10, 1);
    UtRegisterTest("DetectTosTest11", DetectTosTest11, 1);
    UtRegisterTest("DetectTosTest12", DetectTosTest12, 1);
#endif

    return;
}
