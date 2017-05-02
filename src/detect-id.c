/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * Implements the id keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter-common.h"

#include "detect-id.h"
#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */
#define PARSE_REGEX  "^\\s*([0-9]{1,5}|\"[0-9]{1,5}\")\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectIdMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIdSetup (DetectEngineCtx *, Signature *, const char *);
void DetectIdRegisterTests(void);
void DetectIdFree(void *);

static int PrefilterSetupId(SigGroupHead *sgh);
static _Bool PrefilterIdIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for keyword: id
 */
void DetectIdRegister (void)
{
    sigmatch_table[DETECT_ID].name = "id";
    sigmatch_table[DETECT_ID].desc = "match on a specific IP ID value";
    sigmatch_table[DETECT_ID].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#id";
    sigmatch_table[DETECT_ID].Match = DetectIdMatch;
    sigmatch_table[DETECT_ID].Setup = DetectIdSetup;
    sigmatch_table[DETECT_ID].Free  = DetectIdFree;
    sigmatch_table[DETECT_ID].RegisterTests = DetectIdRegisterTests;

    sigmatch_table[DETECT_ID].SupportsPrefilter = PrefilterIdIsPrefilterable;
    sigmatch_table[DETECT_ID].SetupPrefilter = PrefilterSetupId;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match the specified id on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectIdData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIdMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                          const Signature *s, const SigMatchCtx *ctx)
{
    const DetectIdData *id_d = (const DetectIdData *)ctx;

    /**
     * To match a ipv4 packet with a "id" rule
     */
    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    if (id_d->id == IPV4_GET_IPID(p)) {
        SCLogDebug("IPV4 Proto and matched with ip_id: %u.\n",
                    id_d->id);
        return 1;
    }

    return 0;
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectIdData on success
 * \retval NULL on failure
 */
static DetectIdData *DetectIdParse (const char *idstr)
{
    uint32_t temp;
    DetectIdData *id_d = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, idstr, strlen(idstr), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid id option. The id option value must be"
                    " in the range %u - %u",
                    DETECT_IPID_MIN, DETECT_IPID_MAX);
        goto error;
    }


    if (ret > 1) {
        char copy_str[128] = "";
        char *tmp_str;
        res = pcre_copy_substring((char *)idstr, ov, MAX_SUBSTRINGS, 1,
                                    copy_str, sizeof(copy_str));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }

        tmp_str = copy_str;

        /* Let's see if we need to scape "'s */
        if (tmp_str[0] == '"')
        {
            tmp_str[strlen(tmp_str) - 1] = '\0';
            tmp_str += 1;
        }

        /* ok, fill the id data */
        temp = atoi((char *)tmp_str);

        if (temp > DETECT_IPID_MAX) {
            SCLogError(SC_ERR_INVALID_VALUE, "\"id\" option  must be in "
                        "the range %u - %u",
                        DETECT_IPID_MIN, DETECT_IPID_MAX);
            goto error;
        }

        /* We have a correct id option */
        id_d = SCMalloc(sizeof(DetectIdData));
        if (unlikely(id_d == NULL))
            goto error;

        id_d->id = temp;

        SCLogDebug("detect-id: will look for ip_id: %u\n", id_d->id);
    }

    return id_d;

error:
    if (id_d != NULL)
        DetectIdFree(id_d);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectIdSetup (DetectEngineCtx *de_ctx, Signature *s, const char *idstr)
{
    DetectIdData *id_d = NULL;
    SigMatch *sm = NULL;

    id_d = DetectIdParse(idstr);
    if (id_d == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ID;
    sm->ctx = (SigMatchCtx *)id_d;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (id_d != NULL) DetectIdFree(id_d);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIdData
 *
 * \param id_d pointer to DetectIdData
 */
void DetectIdFree(void *ptr)
{
    DetectIdData *id_d = (DetectIdData *)ptr;
    SCFree(id_d);
}

/* prefilter code */

static void
PrefilterPacketIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p)) {
        return;
    }

    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    if (IPV4_GET_IPID(p) == ctx->v1.u16[0])
    {
        SCLogDebug("packet matches IP id %u", ctx->v1.u16[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketIdSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectIdData *a = smctx;
    v->u16[0] = a->id;
}

static _Bool
PrefilterPacketIdCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectIdData *a = smctx;
    if (v.u16[0] == a->id)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupId(SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(sgh, DETECT_ID,
        PrefilterPacketIdSet,
        PrefilterPacketIdCompare,
        PrefilterPacketIdMatch);
}

static _Bool PrefilterIdIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ID:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectIdTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
static int DetectIdTestParse01 (void)
{
    DetectIdData *id_d = NULL;
    id_d = DetectIdParse(" 35402 ");
    if (id_d != NULL &&id_d->id==35402) {
        DetectIdFree(id_d);
        return 1;
    }

    return 0;
}

/**
 * \test DetectIdTestParse02 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectIdTestParse02 (void)
{
    DetectIdData *id_d = NULL;
    id_d = DetectIdParse("65537");
    if (id_d == NULL) {
        DetectIdFree(id_d);
        return 1;
    }

    return 0;
}

/**
 * \test DetectIdTestParse03 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectIdTestParse03 (void)
{
    DetectIdData *id_d = NULL;
    id_d = DetectIdParse("12what?");
    if (id_d == NULL) {
        DetectIdFree(id_d);
        return 1;
    }

    return 0;
}

/**
 * \test DetectIdTestParse04 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option but wrapped with "'s
 */
static int DetectIdTestParse04 (void)
{
    DetectIdData *id_d = NULL;
    /* yep, look if we trim blank spaces correctly and ignore "'s */
    id_d = DetectIdParse(" \"35402\" ");
    if (id_d != NULL &&id_d->id==35402) {
        DetectIdFree(id_d);
        return 1;
    }

    return 0;
}

/**
 * \test DetectIdTestSig01
 * \brief Test to check "id" keyword with constructed packets
 */
static int DetectIdTestMatch01(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_UDP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    /* TCP IP id = 1234 */
    p[0]->ip4h->ip_id = htons(1234);

    /* UDP IP id = 5678 */
    p[1]->ip4h->ip_id = htons(5678);

    /* UDP IP id = 91011 */
    p[2]->ip4h->ip_id = htons(5101);

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; id:1234; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; id:5678; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; id:5101; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {1, 0, 0},
                              /* packet 1 should not match */
                              {0, 1, 0},
                              /* packet 2 should not match */
                              {0, 0, 1} };

    result = UTHGenericTest(p, 3, sigs, sid, (uint32_t *) results, 3);

    UTHFreePackets(p, 3);
end:
    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectId
 */
void DetectIdRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectIdTestParse01", DetectIdTestParse01);
    UtRegisterTest("DetectIdTestParse02", DetectIdTestParse02);
    UtRegisterTest("DetectIdTestParse03", DetectIdTestParse03);
    UtRegisterTest("DetectIdTestParse04", DetectIdTestParse04);
    UtRegisterTest("DetectIdTestMatch01", DetectIdTestMatch01);

#endif /* UNITTESTS */
}
