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
 * Implements the flags keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"

#include "flow-var.h"
#include "decode-events.h"

#include "detect-tcp-flags.h"
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

static int DetectFlagsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlagsSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFlagsFree(void *);

static _Bool PrefilterTcpFlagsIsPrefilterable(const Signature *s);
static int PrefilterSetupTcpFlags(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

/**
 * \brief Registration function for flags: keyword
 */

void DetectFlagsRegister (void)
{
    sigmatch_table[DETECT_FLAGS].name = "tcp.flags";
    sigmatch_table[DETECT_FLAGS].alias = "flags";
    sigmatch_table[DETECT_FLAGS].desc = "detect which flags are set in the TCP header";
    sigmatch_table[DETECT_FLAGS].url = "/rules/header-keywords.html#tcp-flags";
    sigmatch_table[DETECT_FLAGS].Match = DetectFlagsMatch;
    sigmatch_table[DETECT_FLAGS].Setup = DetectFlagsSetup;
    sigmatch_table[DETECT_FLAGS].Free  = DetectFlagsFree;
    sigmatch_table[DETECT_FLAGS].RegisterTests = FlagsRegisterTests;

    sigmatch_table[DETECT_FLAGS].SupportsPrefilter = PrefilterTcpFlagsIsPrefilterable;
    sigmatch_table[DETECT_FLAGS].SetupPrefilter = PrefilterSetupTcpFlags;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

static inline int FlagsMatch(const uint8_t pflags, const uint8_t modifier,
                             const uint8_t dflags, const uint8_t iflags)
{
    if (!dflags && pflags) {
        if(modifier == MODIFIER_NOT) {
            SCReturnInt(1);
        }

        SCReturnInt(0);
    }

    const uint8_t flags = pflags & iflags;

    switch (modifier) {
        case MODIFIER_ANY:
            if ((flags & dflags) > 0) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        case MODIFIER_PLUS:
            if (((flags & dflags) == dflags)) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        case MODIFIER_NOT:
            if ((flags & dflags) != dflags) {
                SCReturnInt(1);
            }
            SCReturnInt(0);

        default:
            SCLogDebug("flags %"PRIu8" and de->flags %"PRIu8"", flags, dflags);
            if (flags == dflags) {
                SCReturnInt(1);
            }
    }

    SCReturnInt(0);
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
static int DetectFlagsMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(0);
    }

    const DetectFlagsData *de = (const DetectFlagsData *)ctx;
    const uint8_t flags = p->tcph->th_flags;

    return FlagsMatch(flags, de->modifier, de->flags, de->ignored_flags);
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
static DetectFlagsData *DetectFlagsParse (const char *rawstr)
{
    SCEnter();

#define MAX_SUBSTRINGS 30
    int ret = 0, found = 0, ignore = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char *ptr;

    char arg1[16] = "";
    char arg2[16] = "";
    char arg3[16] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr),
            0, 0, ov, MAX_SUBSTRINGS);
    SCLogDebug("input '%s', pcre said %d", rawstr, ret);
    if (ret < 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre match failed");
        SCReturnPtr(NULL, "DetectFlagsData");
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        SCReturnPtr(NULL, "DetectFlagsData");
    }
    if (ret >= 2) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            SCReturnPtr(NULL, "DetectFlagsData");
        }
    }
    if (ret >= 3) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, arg3, sizeof(arg3));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            SCReturnPtr(NULL, "DetectFlagsData");
        }
    }
    SCLogDebug("args '%s', '%s', '%s'", arg1, arg2, arg3);

    if (strlen(arg2) == 0) {
        SCLogDebug("empty argument");
        SCReturnPtr(NULL, "DetectFlagsData");
    }

    DetectFlagsData *de = SCMalloc(sizeof(DetectFlagsData));
    if (unlikely(de == NULL))
        goto error;
    memset(de, 0, sizeof(DetectFlagsData));
    de->ignored_flags = 0xff;

    /** First parse args1 */
    ptr = arg1;
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

    /** Second parse first set of flags */
    if (strlen(arg2) > 0) {
        ptr = arg2;
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
                case 'C':
                case 'c':
                    de->flags |= TH_CWR;
                    found++;
                    break;
                case '2':
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

        if (found == 0)
            goto error;
    }

    /** Finally parse ignored flags */
    if (strlen(arg3) > 0) {
        ptr = arg3;

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

        if (ignore == 0) {
            SCLogDebug("ignore == 0");
            goto error;
        }
    }

    SCLogDebug("found %"PRId32" ignore %"PRId32"", found, ignore);
    SCReturnPtr(de, "DetectFlagsData");

error:
    if (de) {
        SCFree(de);
    }
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
static int DetectFlagsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
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

int DetectFlagsSignatureNeedsSynPackets(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
            {
                const DetectFlagsData *fl = (const DetectFlagsData *)sm->ctx;

                if (!(fl->modifier == MODIFIER_NOT) && (fl->flags & TH_SYN)) {
                    return 1;
                }
                break;
            }
        }
    }
    return 0;
}

int DetectFlagsSignatureNeedsSynOnlyPackets(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
            {
                const DetectFlagsData *fl = (const DetectFlagsData *)sm->ctx;

                if (!(fl->modifier == MODIFIER_NOT) && (fl->flags == TH_SYN)) {
                    return 1;
                }
                break;
            }
        }
    }
    return 0;
}

static void
PrefilterPacketFlagsMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    const uint8_t flags = p->tcph->th_flags;
    if (FlagsMatch(flags, ctx->v1.u8[0], ctx->v1.u8[1], ctx->v1.u8[2]))
    {
        SCLogDebug("packet matches TCP flags %02x", ctx->v1.u8[1]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketFlagsSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectFlagsData *a = smctx;
    v->u8[0] = a->modifier;
    v->u8[1] = a->flags;
    v->u8[2] = a->ignored_flags;
    SCLogDebug("v->u8[0] = %02x", v->u8[0]);
}

static _Bool
PrefilterPacketFlagsCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectFlagsData *a = smctx;
    if (v.u8[0] == a->modifier &&
        v.u8[1] == a->flags &&
        v.u8[2] == a->ignored_flags)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTcpFlags(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLAGS,
            PrefilterPacketFlagsSet,
            PrefilterPacketFlagsCompare,
            PrefilterPacketFlagsMatch);

}

static _Bool PrefilterTcpFlagsIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
                return TRUE;
        }
    }
    return FALSE;
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
    DetectFlagsData *de = DetectFlagsParse("S");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->flags == TH_SYN);
    DetectFlagsFree(de);
    PASS;
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
        return 0;
    }

    return 1;
}

/**
 * \test FlagsTestParse03 test if ACK and PUSH are set. Must return success
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse03 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 0;
    }

    /* Error expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
}

/**
 * \test FlagsTestParse05 test if ACK+PUSH and more flags are set. Ignore SYN and RST bits.
 *       Must fails.
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse05 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 0;
    }

    /* Error expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
}

/**
 * \test FlagsTestParse06 test if ACK+PUSH and more flags are set. Ignore URG and RST bits.
 *       Must return success.
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse06 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 0;
    }

    /* Error expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
}

/**
 * \test FlagsTestParse08 test if SYN or RST are set. Must return success.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse08 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 0;
    }

    /* Expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
}

/**
 * \test FlagsTestParse12 check if no flags are set. Must fails.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FlagsTestParse12 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 0;
    }

    /* Expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectFlagsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
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

    ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

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
    UtRegisterTest("FlagsTestParse01", FlagsTestParse01);
    UtRegisterTest("FlagsTestParse02", FlagsTestParse02);
    UtRegisterTest("FlagsTestParse03", FlagsTestParse03);
    UtRegisterTest("FlagsTestParse04", FlagsTestParse04);
    UtRegisterTest("FlagsTestParse05", FlagsTestParse05);
    UtRegisterTest("FlagsTestParse06", FlagsTestParse06);
    UtRegisterTest("FlagsTestParse07", FlagsTestParse07);
    UtRegisterTest("FlagsTestParse08", FlagsTestParse08);
    UtRegisterTest("FlagsTestParse09", FlagsTestParse09);
    UtRegisterTest("FlagsTestParse10", FlagsTestParse10);
    UtRegisterTest("FlagsTestParse11", FlagsTestParse11);
    UtRegisterTest("FlagsTestParse12", FlagsTestParse12);
    UtRegisterTest("FlagsTestParse13", FlagsTestParse13);
    UtRegisterTest("FlagsTestParse14", FlagsTestParse14);
    UtRegisterTest("FlagsTestParse15", FlagsTestParse15);
    UtRegisterTest("FlagsTestParse16", FlagsTestParse16);
    UtRegisterTest("FlagsTestParse17", FlagsTestParse17);
#endif /* UNITTESTS */
}
