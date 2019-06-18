/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-tcpmss.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectTcpmssMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTcpmssSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTcpmssFree (void *);
#ifdef UNITTESTS
void DetectTcpmssRegisterTests (void);
#endif
static int PrefilterSetupTcpmss(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static _Bool PrefilterTcpmssIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for tcpmss: keyword
 */

void DetectTcpmssRegister(void)
{
    sigmatch_table[DETECT_TCPMSS].name = "tcp.mss";
    sigmatch_table[DETECT_TCPMSS].desc = "match on TCP MSS option field";
    sigmatch_table[DETECT_TCPMSS].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#tcpmss";
    sigmatch_table[DETECT_TCPMSS].Match = DetectTcpmssMatch;
    sigmatch_table[DETECT_TCPMSS].Setup = DetectTcpmssSetup;
    sigmatch_table[DETECT_TCPMSS].Free = DetectTcpmssFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TCPMSS].RegisterTests = DetectTcpmssRegisterTests;
#endif
    sigmatch_table[DETECT_TCPMSS].SupportsPrefilter = PrefilterTcpmssIsPrefilterable;
    sigmatch_table[DETECT_TCPMSS].SetupPrefilter = PrefilterSetupTcpmss;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int TcpmssMatch(const uint16_t parg, const uint8_t mode,
        const uint16_t darg1, const uint16_t darg2)
{
    if (mode == DETECT_TCPMSS_EQ && parg == darg1)
        return 1;
    else if (mode == DETECT_TCPMSS_LT && parg < darg1)
        return 1;
    else if (mode == DETECT_TCPMSS_GT && parg > darg1)
        return 1;
    else if (mode == DETECT_TCPMSS_RA && (parg > darg1 && parg < darg2))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match TCPMSS rule option on a packet with those passed via tcpmss:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTcpmssData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTcpmssMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (!(TCP_HAS_MSS(p)))
        return 0;

    uint16_t ptcpmss = TCP_GET_MSS(p);

    const DetectTcpmssData *tcpmssd = (const DetectTcpmssData *)ctx;
    return TcpmssMatch(ptcpmss, tcpmssd->mode, tcpmssd->arg1, tcpmssd->arg2);
}

/**
 * \brief This function is used to parse tcpmss options passed via tcpmss: keyword
 *
 * \param tcpmssstr Pointer to the user provided tcpmss options
 *
 * \retval tcpmssd pointer to DetectTcpmssData on success
 * \retval NULL on failure
 */

static DetectTcpmssData *DetectTcpmssParse (const char *tcpmssstr)
{
    DetectTcpmssData *tcpmssd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, tcpmssstr, strlen(tcpmssstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) tcpmssstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) tcpmssstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) tcpmssstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    tcpmssd = SCMalloc(sizeof (DetectTcpmssData));
    if (unlikely(tcpmssd == NULL))
        goto error;
    tcpmssd->arg1 = 0;
    tcpmssd->arg2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                tcpmssd->mode = DETECT_TCPMSS_LT;
                tcpmssd->arg1 = (uint16_t) atoi(arg3);

                SCLogDebug("tcpmss is %"PRIu8"",tcpmssd->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                tcpmssd->mode = DETECT_TCPMSS_GT;
                tcpmssd->arg1 = (uint16_t) atoi(arg3);

                SCLogDebug("tcpmss is %"PRIu8"",tcpmssd->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                tcpmssd->mode = DETECT_TCPMSS_RA;
                tcpmssd->arg1 = (uint16_t) atoi(arg1);

                tcpmssd->arg2 = (uint16_t) atoi(arg3);
                SCLogDebug("tcpmss is %"PRIu16" to %"PRIu16"",tcpmssd->arg1, tcpmssd->arg2);
                if (tcpmssd->arg1 >= tcpmssd->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid tcpmss range. ");
                    goto error;
                }
                break;
            default:
                tcpmssd->mode = DETECT_TCPMSS_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                tcpmssd->arg1 = (uint16_t) atoi(arg1);
                break;
        }
    } else {
        tcpmssd->mode = DETECT_TCPMSS_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        tcpmssd->arg1 = (uint16_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return tcpmssd;

error:
    if (tcpmssd)
        SCFree(tcpmssd);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief this function is used to atcpmssd the parsed tcpmss data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param tcpmssstr pointer to the user provided tcpmss options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTcpmssSetup (DetectEngineCtx *de_ctx, Signature *s, const char *tcpmssstr)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse(tcpmssstr);
    if (tcpmssd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTcpmssFree(tcpmssd);
        return -1;
    }

    sm->type = DETECT_TCPMSS;
    sm->ctx = (SigMatchCtx *)tcpmssd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTcpmssData
 *
 * \param ptr pointer to DetectTcpmssData
 */
void DetectTcpmssFree(void *ptr)
{
    DetectTcpmssData *tcpmssd = (DetectTcpmssData *)ptr;
    SCFree(tcpmssd);
}

/* prefilter code */

static void
PrefilterPacketTcpmssMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p))
        return;

    if (!(TCP_HAS_MSS(p)))
        return;

    uint16_t ptcpmss = TCP_GET_MSS(p);

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (TcpmssMatch(ptcpmss, ctx->v1.u8[0], ctx->v1.u16[1], ctx->v1.u16[2]))
    {
        SCLogDebug("packet matches tcpmss/hl %u", ptcpmss);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketTcpmssSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTcpmssData *a = smctx;
    v->u8[0] = a->mode;
    v->u16[1] = a->arg1;
    v->u16[2] = a->arg2;
}

static _Bool
PrefilterPacketTcpmssCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTcpmssData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u16[1] == a->arg1 &&
        v.u16[2] == a->arg2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTcpmss(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TCPMSS,
            PrefilterPacketTcpmssSet,
            PrefilterPacketTcpmssCompare,
            PrefilterPacketTcpmssMatch);
}

static _Bool PrefilterTcpmssIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TCPMSS:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "tests/detect-tcpmss.c"
#endif
