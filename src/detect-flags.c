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
 * Implements the flags keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "decode-events.h"

#include "detect-flags.h"
#include "util-unittest.h"

#include "util-debug.h"

/**
 *  Regex (by Brian Rectanus)
 *  flags: [!+*](SAPRFU120)[,SAPRFU12]
 */
#define PARSE_REGEX "^\\s*(?:([\\+\\*!]))?\\s*([SAPRFU120CE\\+\\*!]+)(?:\\s*,\\s*([SAPRFU12CE]+))?\\s*$"

/**
 * Flags args[0] *(3) +(2) !(1)
 *
 */

#define MODIFIER_NOT  1
#define MODIFIER_PLUS 2
#define MODIFIER_ANY  3

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectFlagsMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFlagsSetup (DetectEngineCtx *, Signature *, char *);
static void DetectFlagsFree(void *);

/**
 * \brief Registration function for flags: keyword
 */

void DetectFlagsRegister (void)
{
    sigmatch_table[DETECT_FLAGS].name = "flags";
    sigmatch_table[DETECT_FLAGS].Match = DetectFlagsMatch;
    sigmatch_table[DETECT_FLAGS].Setup = DetectFlagsSetup;
    sigmatch_table[DETECT_FLAGS].Free  = DetectFlagsFree;
    sigmatch_table[DETECT_FLAGS].RegisterTests = FlagsRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    return;

}

/**
 * \internal
 * \brief This function is used to match flags on a packet with those passed via flags:
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
static int DetectFlagsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    uint8_t flags = 0;
    const DetectFlagsData *de = (const DetectFlagsData *)ctx;

    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(0);
    }

    flags = p->tcph->th_flags;

    if (!de->flags && flags) {
        if(de->modifier == MODIFIER_NOT) {
            SCReturnInt(1);
        }

        SCReturnInt(0);
    }

    flags &= de->ignored_flags;

    switch (de->modifier) {
        case MODIFIER_ANY:
            if ((flags & de->flags) > 0) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        case MODIFIER_PLUS:
            if (((flags & de->flags) == de->flags)) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        case MODIFIER_NOT:
            if ((flags & de->flags) != de->flags) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        default:
            SCLogDebug("flags %"PRIu8" and de->flags %"PRIu8"",flags,de->flags);
            if (flags == de->flags) {
                SCReturnInt(1);
            }
    }

    SCReturnInt(0);
}

/**
 * \internal
 * \brief This function is used to parse flags options passed via flags: keyword
 *
 * \param rawstr Pointer to the user provided flags options
 *
 * \retval de pointer to DetectFlagsData on success
 * \retval NULL on failure
 */
static DetectFlagsData *DetectFlagsParse (char *rawstr)
{
    SCEnter();

    DetectFlagsData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, found = 0, ignore = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr = NULL;
    char *args[3] = { NULL, NULL, NULL };
    char *ptr;
    int i;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr),
            0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre match failed");
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {

        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,i + 1,
                &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        args[i] = (char *)str_ptr;
    }

    if(args[1] == NULL) {
        SCLogDebug("args[1] == NULL");
        goto error;
    }

    de = SCMalloc(sizeof(DetectFlagsData));
    if (unlikely(de == NULL))
        goto error;

    memset(de,0,sizeof(DetectFlagsData));

    de->ignored_flags = 0xff;

    /** First parse args[0] */

    if(args[0])   {

        ptr = args[0];

        while (*ptr != '\0') {
            switch (*ptr) {
                case 'S':
                case 's':
                    de->flags |= TH_SYN;
                    found++;
                    break;
                case 'A':
                case 'a':
                    de->flags |= TH_ACK;
                    found++;
                    break;
                case 'F':
                case 'f':
                    de->flags |= TH_FIN;
                    found++;
                    break;
                case 'R':
                case 'r':
                    de->flags |= TH_RST;
                    found++;
                    break;
                case 'P':
                case 'p':
                    de->flags |= TH_PUSH;
                    found++;
                    break;
                case 'U':
                case 'u':
                    de->flags |= TH_URG;
                    found++;
                    break;
                case '1':
                    de->flags |= TH_CWR;
                    found++;
                    break;
                case '2':
                    de->flags |= TH_ECN;
                    found++;
                    break;
                case 'C':
                case 'c':
                    de->flags |= TH_CWR;
                    found++;
                    break;
                case 'E':
                case 'e':
                    de->flags |= TH_ECN;
                    found++;
                    break;
                case '0':
                    de->flags = 0;
                    found++;
                    break;

                case '!':
                    de->modifier = MODIFIER_NOT;
                    break;
                case '+':
                    de->modifier = MODIFIER_PLUS;
                    break;
                case '*':
                    de->modifier = MODIFIER_ANY;
                    break;
            }
            ptr++;
        }

    }

    /** Second parse first set of flags */

    ptr = args[1];

    while (*ptr != '\0') {
        switch (*ptr) {
            case 'S':
            case 's':
                de->flags |= TH_SYN;
                found++;
                break;
            case 'A':
            case 'a':
                de->flags |= TH_ACK;
                found++;
                break;
            case 'F':
            case 'f':
                de->flags |= TH_FIN;
                found++;
                break;
            case 'R':
            case 'r':
                de->flags |= TH_RST;
                found++;
                break;
            case 'P':
            case 'p':
                de->flags |= TH_PUSH;
                found++;
                break;
            case 'U':
            case 'u':
                de->flags |= TH_URG;
                found++;
                break;
            case '1':
                de->flags |= TH_CWR;
                found++;
                break;
            case '2':
                de->flags |= TH_ECN;
                found++;
                break;
            case 'C':
            case 'c':
                de->flags |= TH_CWR;
                found++;
                break;
            case 'E':
            case 'e':
                de->flags |= TH_ECN;
                found++;
                break;
            case '0':
                de->flags = 0;
                found++;
                break;

            case '!':
                if (de->modifier != 0) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "\"flags\" supports only"
                            " one modifier at a time");
                    goto error;
                }
                de->modifier = MODIFIER_NOT;
                SCLogDebug("NOT modifier is set");
                break;
            case '+':
                if (de->modifier != 0) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "\"flags\" supports only"
                            " one modifier at a time");
                    goto error;
                }
                de->modifier = MODIFIER_PLUS;
                SCLogDebug("PLUS modifier is set");
                break;
            case '*':
                if (de->modifier != 0) {
                    SCLogError(SC_ERR_FLAGS_MODIFIER, "\"flags\" supports only"
                            " one modifier at a time");
                    goto error;
                }
                de->modifier = MODIFIER_ANY;
                SCLogDebug("ANY modifier is set");
                break;
            default:
                break;
        }
        ptr++;
    }

    if(found == 0)
        goto error;

    /** Finally parse ignored flags */

    if(args[2])    {

        ptr = args[2];

        while (*ptr != '\0') {
            switch (*ptr) {
                case 'S':
                case 's':
                    de->ignored_flags &= ~TH_SYN;
                    ignore++;
                    break;
                case 'A':
                case 'a':
                    de->ignored_flags &= ~TH_ACK;
                    ignore++;
                    break;
                case 'F':
                case 'f':
                    de->ignored_flags &= ~TH_FIN;
                    ignore++;
                    break;
                case 'R':
                case 'r':
                    de->ignored_flags &= ~TH_RST;
                    ignore++;
                    break;
                case 'P':
                case 'p':
                    de->ignored_flags &= ~TH_PUSH;
                    ignore++;
                    break;
                case 'U':
                case 'u':
                    de->ignored_flags &= ~TH_URG;
                    ignore++;
                    break;
                case '1':
                    de->ignored_flags &= ~TH_CWR;
                    ignore++;
                    break;
                case '2':
                    de->ignored_flags &= ~TH_ECN;
                    ignore++;
                    break;
                case 'C':
                case 'c':
                    de->ignored_flags &= ~TH_CWR;
                    ignore++;
                    break;
                case 'E':
                case 'e':
                    de->ignored_flags &= ~TH_ECN;
                    ignore++;
                    break;
                case '0':
                    break;
                default:
                    break;
            }
            ptr++;
        }

        if(ignore == 0) {
            SCLogDebug("ignore == 0");
            goto error;
        }
    }

    for (i = 0; i < (ret - 1); i++){
        SCLogDebug("args[%"PRId32"] = %s",i, args[i]);
        if (args[i] != NULL) SCFree(args[i]);
    }

    SCLogDebug("found %"PRId32" ignore %"PRId32"", found, ignore);
    SCReturnPtr(de, "DetectFlagsData");

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) SCFree(args[i]);
    }
    if (de) SCFree(de);
    SCReturnPtr(NULL, "DetectFlagsData");
}

/**
 * \internal
 * \brief this function is used to add the parsed flags into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided flags options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFlagsSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectFlagsParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectFlagsData
 *
 * \param de pointer to DetectFlagsData
 */
static void DetectFlagsFree(void *de_ptr)
{
    DetectFlagsData *de = (DetectFlagsData *)de_ptr;
    if(de) SCFree(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test FlagsTestParse01 is a test for a  valid flags value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse01 (void)
{
    DetectFlagsData *de = NULL;
    de = DetectFlagsParse("S");
    if (de && (de->flags == TH_SYN) ) {
        DetectFlagsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test FlagsTestParse02 is a test for an invalid flags value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse02 (void)
{
    DetectFlagsData *de = NULL;
    de = DetectFlagsParse("G");
    if (de) {
        DetectFlagsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test FlagsTestParse03 test if ACK and PUSH are set. Must return success
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse03 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ACK|TH_PUSH|TH_SYN|TH_RST;

    de = DetectFlagsParse("AP+");

    if (de == NULL || (de->flags != (TH_ACK|TH_PUSH)) )
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse04 check if ACK bit is set. Must fails.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse04 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN;

    de = DetectFlagsParse("A");

    if (de == NULL || de->flags != TH_ACK)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse05 test if ACK+PUSH and more flags are set. Ignore SYN and RST bits.
 *       Must fails.
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse05 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ACK|TH_PUSH|TH_SYN|TH_RST;

    de = DetectFlagsParse("+AP,SR");

    if (de == NULL || (de->modifier != MODIFIER_PLUS) || (de->flags != (TH_ACK|TH_PUSH)) || (de->ignored_flags != (TH_SYN|TH_RST)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse06 test if ACK+PUSH and more flags are set. Ignore URG and RST bits.
 *       Must return success.
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse06 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ACK|TH_PUSH|TH_SYN|TH_RST;

    de = DetectFlagsParse("+AP,UR");

    if (de == NULL || (de->modifier != MODIFIER_PLUS) || (de->flags != (TH_ACK|TH_PUSH)) || ((0xff - de->ignored_flags) != (TH_URG|TH_RST)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse07 test if SYN or RST are set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse07 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN|TH_RST;

    de = DetectFlagsParse("*AP");

    if (de == NULL || (de->modifier != MODIFIER_ANY) || (de->flags != (TH_ACK|TH_PUSH)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse08 test if SYN or RST are set. Must return success.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse08 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN|TH_RST;

    de = DetectFlagsParse("*SA");

    if (de == NULL || (de->modifier != MODIFIER_ANY) || (de->flags != (TH_ACK|TH_SYN)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse09 test if SYN and RST are not set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse09 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN|TH_RST;

    de = DetectFlagsParse("!PA");

    if (de == NULL || (de->modifier != MODIFIER_NOT) || (de->flags != (TH_ACK|TH_PUSH)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse10 test if ACK and PUSH are not set. Must return success.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse10 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN|TH_RST;

    de = DetectFlagsParse("!AP");

    if (de == NULL || (de->modifier != MODIFIER_NOT) || (de->flags != (TH_ACK|TH_PUSH)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse11 test if ACK or PUSH are set. Ignore SYN and RST. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse11 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN|TH_RST|TH_URG;

    de = DetectFlagsParse("*AP,SR");

    if (de == NULL || (de->modifier != MODIFIER_ANY) || (de->flags != (TH_ACK|TH_PUSH)) || ((0xff - de->ignored_flags) != (TH_SYN|TH_RST)))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FlagsTestParse12 check if no flags are set. Must fails.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse12 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_SYN;

    de = DetectFlagsParse("0");

    if (de == NULL || de->flags != 0) {
        printf("de setup: ");
        goto error;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test test for a  valid flags value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse13 (void)
{
    DetectFlagsData *de = NULL;
    de = DetectFlagsParse("+S*");
    if (de != NULL) {
        DetectFlagsFree(de);
        return 0;
    }

    return 1;
}

/**
 * \test Parse 'C' and 'E' flags.
 *
 *  \retval 1 on success.
 *  \retval 0 on failure.
 */
static int FlagsTestParse14(void)
{
    DetectFlagsData *de = DetectFlagsParse("CE");
    if (de != NULL && (de->flags == (TH_CWR | TH_ECN)) ) {
        DetectFlagsFree(de);
        return 1;
    }

    return 0;
}

static int FlagsTestParse15(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ECN | TH_CWR | TH_SYN | TH_RST;

    de = DetectFlagsParse("EC+");

    if (de == NULL || (de->flags != (TH_ECN | TH_CWR)) )
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if (ret) {
        if (de)
            SCFree(de);
        if (sm)
            SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de)
        SCFree(de);
    if (sm)
        SCFree(sm);
    SCFree(p);
    return 0;
}

static int FlagsTestParse16(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ECN | TH_SYN | TH_RST;

    de = DetectFlagsParse("EC*");

    if (de == NULL || (de->flags != (TH_ECN | TH_CWR)) )
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if (ret) {
        if (de)
            SCFree(de);
        if (sm)
            SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de)
        SCFree(de);
    if (sm)
        SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test Negative test.
 */
static int FlagsTestParse17(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    p->ip4h = &ipv4h;
    p->tcph = &tcph;
    p->tcph->th_flags = TH_ECN | TH_SYN | TH_RST;

    de = DetectFlagsParse("EC+");

    if (de == NULL || (de->flags != (TH_ECN | TH_CWR)) )
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFlagsMatch(&tv, NULL, p, NULL, sm->ctx);

    if (ret == 0) {
        if (de)
            SCFree(de);
        if (sm)
            SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    if (de)
        SCFree(de);
    if (sm)
        SCFree(sm);
    SCFree(p);
    return 0;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for Flags
 */
void FlagsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlagsTestParse01", FlagsTestParse01, 1);
    UtRegisterTest("FlagsTestParse02", FlagsTestParse02, 0);
    UtRegisterTest("FlagsTestParse03", FlagsTestParse03, 1);
    UtRegisterTest("FlagsTestParse04", FlagsTestParse04, 0);
    UtRegisterTest("FlagsTestParse05", FlagsTestParse05, 0);
    UtRegisterTest("FlagsTestParse06", FlagsTestParse06, 1);
    UtRegisterTest("FlagsTestParse07", FlagsTestParse07, 0);
    UtRegisterTest("FlagsTestParse08", FlagsTestParse08, 1);
    UtRegisterTest("FlagsTestParse09", FlagsTestParse09, 1);
    UtRegisterTest("FlagsTestParse10", FlagsTestParse10, 1);
    UtRegisterTest("FlagsTestParse11", FlagsTestParse11, 0);
    UtRegisterTest("FlagsTestParse12", FlagsTestParse12, 0);
    UtRegisterTest("FlagsTestParse13", FlagsTestParse13, 1);
    UtRegisterTest("FlagsTestParse14", FlagsTestParse14, 1);
    UtRegisterTest("FlagsTestParse15", FlagsTestParse15, 1);
    UtRegisterTest("FlagsTestParse16", FlagsTestParse16, 1);
    UtRegisterTest("FlagsTestParse17", FlagsTestParse17, 1);
#endif /* UNITTESTS */
}
