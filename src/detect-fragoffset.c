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
 * Implements fragoffset keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-fragoffset.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(?:(<|>))?\\s*([0-9]+)"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFragOffsetMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFragOffsetSetup(DetectEngineCtx *, Signature *, char *);
void DetectFragOffsetRegisterTests(void);
void DetectFragOffsetFree(void *);

/**
 * \brief Registration function for fragoffset
 */
void DetectFragOffsetRegister (void)
{
    sigmatch_table[DETECT_FRAGOFFSET].name = "fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].desc = "match on specific decimal values of the IP fragment offset field";
    sigmatch_table[DETECT_FRAGOFFSET].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#Fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].Match = DetectFragOffsetMatch;
    sigmatch_table[DETECT_FRAGOFFSET].Setup = DetectFragOffsetSetup;
    sigmatch_table[DETECT_FRAGOFFSET].Free = DetectFragOffsetFree;
    sigmatch_table[DETECT_FRAGOFFSET].RegisterTests = DetectFragOffsetRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE,"pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY,"pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
}

/**
 * \brief This function is used to match fragoffset rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFragOffsetData
 *
 * \retval 0 no match or frag is not set
 * \retval 1 match
 *
 */
int DetectFragOffsetMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    uint16_t frag = 0;
    const DetectFragOffsetData *fragoff = (const DetectFragOffsetData *)ctx;

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    if (PKT_IS_IPV4(p)) {
        frag = IPV4_GET_IPOFFSET(p);
    } else if (PKT_IS_IPV6(p)) {
        if(IPV6_EXTHDR_FH(p)) {
            frag = IPV6_EXTHDR_GET_FH_OFFSET(p);
        } else {
            return 0;
        }
    } else {
        SCLogDebug("No IPv4 or IPv6 packet");
        return 0;
    }

    switch (fragoff->mode)  {
        case FRAG_LESS:
            if (frag < fragoff->frag_off) return 1;
            break;
        case FRAG_MORE:
            if (frag > fragoff->frag_off) return 1;
            break;
        default:
            if (frag == fragoff->frag_off) return 1;
    }

    return 0;
}

/**
 * \brief This function is used to parse fragoffset option passed via fragoffset: keyword
 *
 * \param fragoffsetstr Pointer to the user provided fragoffset options
 *
 * \retval fragoff pointer to DetectFragOffsetData on success
 * \retval NULL on failure
 */
DetectFragOffsetData *DetectFragOffsetParse (char *fragoffsetstr)
{
    DetectFragOffsetData *fragoff = NULL;
    char *substr[3] = {NULL, NULL, NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    const char *str_ptr;
    char *mode = NULL;

    ret = pcre_exec(parse_regex, parse_regex_study, fragoffsetstr, strlen(fragoffsetstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH,"Parse error %s", fragoffsetstr);
        goto error;
    }

    for (i = 1; i < ret; i++) {
        res = pcre_get_substring((char *)fragoffsetstr, ov, MAX_SUBSTRINGS, i, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_get_substring failed");
            goto error;
        }
        substr[i-1] = (char *)str_ptr;
    }

    fragoff = SCMalloc(sizeof(DetectFragOffsetData));
    if (unlikely(fragoff == NULL))
        goto error;

    fragoff->frag_off = 0;
    fragoff->mode = 0;

    mode = substr[0];

    if(mode != NULL)    {

        while(*mode != '\0')    {
            switch(*mode)   {
                case '>':
                    fragoff->mode = FRAG_MORE;
                    break;
                case '<':
                    fragoff->mode = FRAG_LESS;
                    break;
            }
            mode++;
        }
    }

    if (ByteExtractStringUint16(&fragoff->frag_off, 10, 0, substr[1]) < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified frag offset %s is not "
                                        "valid", substr[1]);
        goto error;
    }

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) SCFree(substr[i]);
    }

    return fragoff;

error:
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) SCFree(substr[i]);
    }
    if (fragoff != NULL) DetectFragOffsetFree(fragoff);
    return NULL;

}

/**
 * \brief this function is used to add the parsed fragoffset data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param fragoffsetstr pointer to the user provided fragoffset option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFragOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, char *fragoffsetstr)
{
    DetectFragOffsetData *fragoff = NULL;
    SigMatch *sm = NULL;

    fragoff = DetectFragOffsetParse(fragoffsetstr);
    if (fragoff == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_FRAGOFFSET;
    sm->ctx = (SigMatchCtx *)fragoff;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (fragoff != NULL) DetectFragOffsetFree(fragoff);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFragOffsetData
 *
 * \param ptr pointer to DetectFragOffsetData
 */
void DetectFragOffsetFree (void *ptr)
{
    DetectFragOffsetData *fragoff = (DetectFragOffsetData *)ptr;
    SCFree(fragoff);
}

#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectFragOffsetParseTest01 is a test for setting a valid fragoffset value
 */
int DetectFragOffsetParseTest01 (void)
{
    DetectFragOffsetData *fragoff = NULL;
    fragoff = DetectFragOffsetParse("300");
    if (fragoff != NULL && fragoff->frag_off == 300) {
        DetectFragOffsetFree(fragoff);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFragOffsetParseTest02 is a test for setting a valid fragoffset value
 *       with spaces all around
 */
int DetectFragOffsetParseTest02 (void)
{
    DetectFragOffsetData *fragoff = NULL;
    fragoff = DetectFragOffsetParse(">300");
    if (fragoff != NULL && fragoff->frag_off == 300 && fragoff->mode == FRAG_MORE) {
        DetectFragOffsetFree(fragoff);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFragOffsetParseTest03 is a test for setting an invalid fragoffset value
 */
int DetectFragOffsetParseTest03 (void)
{
    DetectFragOffsetData *fragoff = NULL;
    fragoff = DetectFragOffsetParse("badc");
    if (fragoff != NULL) {
        DetectFragOffsetFree(fragoff);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFragOffsetMatchTest01 is a test for checking the working of
 *       fragoffset keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
int DetectFragOffsetMatchTest01 (void)
{
    int result = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = 0x01020304;
    p->dst.addr_data32[0] = 0x04030201;

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    ip4h.ip_off = 0x2222;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ip any any -> any any (fragoffset:546; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx, "alert ip any any -> any any (fragoffset:5000; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 0) {
        printf("sid 1 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2)) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FlowShutdown();
end:
    SCFree(p);
    return result;

}
#endif /* UNITTESTS */

void DetectFragOffsetRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectFragOffsetParseTest01", DetectFragOffsetParseTest01, 1);
    UtRegisterTest("DetectFragOffsetParseTest02", DetectFragOffsetParseTest02, 1);
    UtRegisterTest("DetectFragOffsetParseTest03", DetectFragOffsetParseTest03, 0);
    UtRegisterTest("DetectFragOffsetMatchTest01", DetectFragOffsetMatchTest01, 1);
#endif /* UNITTESTS */
}

