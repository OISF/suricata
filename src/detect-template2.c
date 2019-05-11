/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author XXX
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-template2.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectTemplate2Match (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTemplate2Setup (DetectEngineCtx *, Signature *, const char *);
void DetectTemplate2Free (void *);
#ifdef UNITTESTS
void DetectTemplate2RegisterTests (void);
#endif
static int PrefilterSetupTemplate2(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static _Bool PrefilterTemplate2IsPrefilterable(const Signature *s);

/**
 * \brief Registration function for template2: keyword
 */

void DetectTemplate2Register(void)
{
    sigmatch_table[DETECT_TEMPLATE2].name = "template2";
    sigmatch_table[DETECT_TEMPLATE2].desc = "TODO describe the keyword";
    sigmatch_table[DETECT_TEMPLATE2].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#template2";
    sigmatch_table[DETECT_TEMPLATE2].Match = DetectTemplate2Match;
    sigmatch_table[DETECT_TEMPLATE2].Setup = DetectTemplate2Setup;
    sigmatch_table[DETECT_TEMPLATE2].Free = DetectTemplate2Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TEMPLATE2].RegisterTests = DetectTemplate2RegisterTests;
#endif
    sigmatch_table[DETECT_TEMPLATE2].SupportsPrefilter = PrefilterTemplate2IsPrefilterable;
    sigmatch_table[DETECT_TEMPLATE2].SetupPrefilter = PrefilterSetupTemplate2;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int Template2Match(const uint8_t parg, const uint8_t mode,
        const uint8_t darg1, const uint8_t darg2)
{
    if (mode == DETECT_TEMPLATE2_EQ && parg == darg1)
        return 1;
    else if (mode == DETECT_TEMPLATE2_LT && parg < darg1)
        return 1;
    else if (mode == DETECT_TEMPLATE2_GT && parg > darg1)
        return 1;
    else if (mode == DETECT_TEMPLATE2_RA && (parg > darg1 && parg < darg2))
        return 1;

    return 0;
}

/**
 * \brief This function is used to match TEMPLATE2 rule option on a packet with those passed via template2:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTemplate2Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTemplate2Match (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    /* TODO replace this */
    uint8_t ptemplate2;
    if (PKT_IS_IPV4(p)) {
        ptemplate2 = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptemplate2 = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectTemplate2Data *template2d = (const DetectTemplate2Data *)ctx;
    return Template2Match(ptemplate2, template2d->mode, template2d->arg1, template2d->arg2);
}

/**
 * \brief This function is used to parse template2 options passed via template2: keyword
 *
 * \param template2str Pointer to the user provided template2 options
 *
 * \retval template2d pointer to DetectTemplate2Data on success
 * \retval NULL on failure
 */

static DetectTemplate2Data *DetectTemplate2Parse (const char *template2str)
{
    DetectTemplate2Data *template2d = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, template2str, strlen(template2str), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) template2str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) template2str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) template2str, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    template2d = SCMalloc(sizeof (DetectTemplate2Data));
    if (unlikely(template2d == NULL))
        goto error;
    template2d->arg1 = 0;
    template2d->arg2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                template2d->mode = DETECT_TEMPLATE2_LT;
                template2d->arg1 = (uint8_t) atoi(arg3);

                SCLogDebug("template2 is %"PRIu8"",template2d->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                template2d->mode = DETECT_TEMPLATE2_GT;
                template2d->arg1 = (uint8_t) atoi(arg3);

                SCLogDebug("template2 is %"PRIu8"",template2d->arg1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                template2d->mode = DETECT_TEMPLATE2_RA;
                template2d->arg1 = (uint8_t) atoi(arg1);

                template2d->arg2 = (uint8_t) atoi(arg3);
                SCLogDebug("template2 is %"PRIu8" to %"PRIu8"",template2d->arg1, template2d->arg2);
                if (template2d->arg1 >= template2d->arg2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid template2 range. ");
                    goto error;
                }
                break;
            default:
                template2d->mode = DETECT_TEMPLATE2_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                template2d->arg1 = (uint8_t) atoi(arg1);
                break;
        }
    } else {
        template2d->mode = DETECT_TEMPLATE2_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        template2d->arg1 = (uint8_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return template2d;

error:
    if (template2d)
        SCFree(template2d);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief this function is used to atemplate2d the parsed template2 data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param template2str pointer to the user provided template2 options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTemplate2Setup (DetectEngineCtx *de_ctx, Signature *s, const char *template2str)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse(template2str);
    if (template2d == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTemplate2Free(template2d);
        return -1;
    }

    sm->type = DETECT_TEMPLATE2;
    sm->ctx = (SigMatchCtx *)template2d;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTemplate2Data
 *
 * \param ptr pointer to DetectTemplate2Data
 */
void DetectTemplate2Free(void *ptr)
{
    DetectTemplate2Data *template2d = (DetectTemplate2Data *)ptr;
    SCFree(template2d);
}

/* prefilter code */

static void
PrefilterPacketTemplate2Match(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t ptemplate2;
/* TODO update */
    if (PKT_IS_IPV4(p)) {
        ptemplate2 = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        ptemplate2 = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    /* during setup Suricata will automatically see if there is another
     * check that can be added: alproto, sport or dport */
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    /* if we match, add all the sigs that use this prefilter. This means
     * that these will be inspected further */
    if (Template2Match(ptemplate2, ctx->v1.u8[0], ctx->v1.u8[1], ctx->v1.u8[2]))
    {
        SCLogDebug("packet matches template2/hl %u", ptemplate2);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketTemplate2Set(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTemplate2Data *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->arg1;
    v->u8[2] = a->arg2;
}

static _Bool
PrefilterPacketTemplate2Compare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTemplate2Data *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->arg1 &&
        v.u8[2] == a->arg2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTemplate2(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_TEMPLATE2,
            PrefilterPacketTemplate2Set,
            PrefilterPacketTemplate2Compare,
            PrefilterPacketTemplate2Match);
}

static _Bool PrefilterTemplate2IsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TEMPLATE2:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "tests/detect-template2.c"
#endif

