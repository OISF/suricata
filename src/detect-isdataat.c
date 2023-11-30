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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Implements isdataat keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "app-layer.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-isdataat.h"
#include "detect-content.h"
#include "detect-bytetest.h"
#include "detect-uricontent.h"
#include "detect-engine-build.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-byte.h"
#include "detect-pcre.h"
#include "detect-byte.h"

/**
 * \brief Regex for parsing our isdataat options
 */
#define PARSE_REGEX  "^\\s*!?([^\\s,]+)\\s*(,\\s*relative)?\\s*(,\\s*rawbytes\\s*)?\\s*$"

static DetectParseRegex parse_regex;

int DetectIsdataatSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIsdataatRegisterTests(void);
static void DetectAbsentRegisterTests(void);
#endif
void DetectIsdataatFree(DetectEngineCtx *, void *);

static int DetectEndsWithSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr);

static void DetectAbsentFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

static int DetectAbsentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    if (s->init_data->list == DETECT_SM_LIST_NOTSET) {
        SCLogError("no buffer for absent keyword");
        return -1;
    }

    if (DetectBufferGetActiveList(de_ctx, s) == -1)
        return -1;

    bool or_else;
    if (optstr == NULL) {
        or_else = false;
    } else if (strcmp(optstr, "or_else") == 0) {
        or_else = true;
    } else {
        SCLogError("unhandled value for absent keyword: %s", optstr);
        return -1;
    }
    if (s->init_data->curbuf == NULL || s->init_data->list != (int)s->init_data->curbuf->id) {
        SCLogError("unspected buffer for absent keyword");
        return -1;
    }
    const DetectBufferType *b = DetectEngineBufferTypeGetById(de_ctx, s->init_data->list);
    if (!b || b->frame) {
        SCLogError("absent does not work with frames");
        return -1;
    }
    if (s->init_data->curbuf->tail != NULL) {
        SCLogError("absent must come first right after buffer");
        return -1;
    }
    DetectAbsentData *dad = SCMalloc(sizeof(DetectAbsentData));
    if (unlikely(dad == NULL))
        return -1;

    dad->or_else = or_else;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ABSENT, (SigMatchCtx *)dad, s->init_data->list) ==
            NULL) {
        DetectAbsentFree(de_ctx, dad);
        return -1;
    }
    return 0;
}

bool DetectAbsentValidateContentCallback(Signature *s, const SignatureInitDataBuffer *b)
{
    bool has_other = false;
    bool only_absent = false;
    bool has_absent = false;
    for (const SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_ABSENT) {
            has_absent = true;
            const DetectAbsentData *dad = (const DetectAbsentData *)sm->ctx;
            if (!dad->or_else) {
                only_absent = true;
            }
        } else {
            has_other = true;
            if (sm->type == DETECT_CONTENT) {
                const DetectContentData *cd = (DetectContentData *)sm->ctx;
                if ((cd->flags & DETECT_CONTENT_FAST_PATTERN)) {
                    SCLogError("signature can't have absent and fast_pattern on the same buffer");
                    return false;
                }
            }
        }
    }

    if (only_absent && has_other) {
        SCLogError("signature can't have a buffer only absent and tested otherwise");
        return false;
    } else if (has_absent && !only_absent && !has_other) {
        SCLogError("signature with absent: or_else expects something else to test on");
        return false;
    }
    return true;
}

/**
 * \brief Registration function for isdataat: keyword
 */
void DetectIsdataatRegister(void)
{
    sigmatch_table[DETECT_ISDATAAT].name = "isdataat";
    sigmatch_table[DETECT_ISDATAAT].desc = "check if there is still data at a specific part of the payload";
    sigmatch_table[DETECT_ISDATAAT].url = "/rules/payload-keywords.html#isdataat";
    /* match is handled in DetectEngineContentInspection() */
    sigmatch_table[DETECT_ISDATAAT].Match = NULL;
    sigmatch_table[DETECT_ISDATAAT].Setup = DetectIsdataatSetup;
    sigmatch_table[DETECT_ISDATAAT].Free  = DetectIsdataatFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ISDATAAT].RegisterTests = DetectIsdataatRegisterTests;
#endif
    sigmatch_table[DETECT_ENDS_WITH].name = "endswith";
    sigmatch_table[DETECT_ENDS_WITH].desc = "make sure the previous content matches exactly at the end of the buffer";
    sigmatch_table[DETECT_ENDS_WITH].url = "/rules/payload-keywords.html#endswith";
    sigmatch_table[DETECT_ENDS_WITH].Setup = DetectEndsWithSetup;
    sigmatch_table[DETECT_ENDS_WITH].flags = SIGMATCH_NOOPT;

    sigmatch_table[DETECT_ABSENT].name = "absent";
    sigmatch_table[DETECT_ABSENT].desc = "test if the buffer is absent";
    sigmatch_table[DETECT_ABSENT].url = "/rules/payload-keywords.html#absent";
    sigmatch_table[DETECT_ABSENT].Setup = DetectAbsentSetup;
    sigmatch_table[DETECT_ABSENT].Free = DetectAbsentFree;
    sigmatch_table[DETECT_ABSENT].flags = SIGMATCH_OPTIONAL_OPT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ABSENT].RegisterTests = DetectAbsentRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to parse isdataat options passed via isdataat: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param isdataatstr Pointer to the user provided isdataat options
 *
 * \retval idad pointer to DetectIsdataatData on success
 * \retval NULL on failure
 */
static DetectIsdataatData *DetectIsdataatParse (DetectEngineCtx *de_ctx, const char *isdataatstr, char **offset)
{
    DetectIsdataatData *idad = NULL;
    char *args[3] = {NULL,NULL,NULL};
    int res = 0;
    size_t pcre2_len;
    int i=0;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, isdataatstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError("pcre_exec parse error, ret %" PRId32 ", string %s", ret, isdataatstr);
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre2_substring_get_bynumber(match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }
        args[0] = (char *)str_ptr;


        if (ret > 2) {
            res = pcre2_substring_get_bynumber(match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError("pcre2_substring_get_bynumber failed");
                goto error;
            }
            args[1] = (char *)str_ptr;
        }
        if (ret > 3) {
            res = pcre2_substring_get_bynumber(match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0) {
                SCLogError("pcre2_substring_get_bynumber failed");
                goto error;
            }
            args[2] = (char *)str_ptr;
        }

        idad = SCMalloc(sizeof(DetectIsdataatData));
        if (unlikely(idad == NULL))
            goto error;

        idad->flags = 0;
        idad->dataat = 0;

        if (args[0][0] != '-' && isalpha((unsigned char)args[0][0])) {
            if (offset == NULL) {
                SCLogError("isdataat supplied with "
                           "var name for offset.  \"offset\" argument supplied to "
                           "this function has to be non-NULL");
                goto error;
            }
            *offset = SCStrdup(args[0]);
            if (*offset == NULL)
                goto error;
        } else {
            if (StringParseUint16(&idad->dataat, 10,
                                        strlen(args[0]), args[0]) < 0 ) {
                SCLogError("isdataat out of range");
                SCFree(idad);
                idad = NULL;
                goto error;
            }
        }

        if (args[1] !=NULL) {
            idad->flags |= ISDATAAT_RELATIVE;

            if(args[2] !=NULL)
                idad->flags |= ISDATAAT_RAWBYTES;
        }

        if (isdataatstr[0] == '!') {
            idad->flags |= ISDATAAT_NEGATED;
        }

        for (i = 0; i < (ret -1); i++) {
            if (args[i] != NULL)
                pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
        }

        pcre2_match_data_free(match);
        return idad;

    }

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    for (i = 0; i < (ret -1) && i < 3; i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }

    if (idad != NULL)
        DetectIsdataatFree(de_ctx, idad);
    return NULL;

}

/**
 * \brief This function is used to add the parsed isdataatdata into the current
 *        signature.
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param isdataatstr pointer to the user provided isdataat options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectIsdataatSetup (DetectEngineCtx *de_ctx, Signature *s, const char *isdataatstr)
{
    SigMatch *prev_pm = NULL;
    DetectIsdataatData *idad = NULL;
    char *offset = NULL;
    int ret = -1;

    idad = DetectIsdataatParse(de_ctx, isdataatstr, &offset);
    if (idad == NULL)
        return -1;

    int sm_list;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto end;
        sm_list = s->init_data->list;

        if (idad->flags & ISDATAAT_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE, -1);
        }
    } else if (idad->flags & ISDATAAT_RELATIVE) {
        prev_pm = DetectGetLastSMFromLists(s,
            DETECT_CONTENT, DETECT_PCRE,
            DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
            DETECT_ISDATAAT, DETECT_BYTEMATH, -1);
        if (prev_pm == NULL)
            sm_list = DETECT_SM_LIST_PMATCH;
        else {
            sm_list = SigMatchListSMBelongsTo(s, prev_pm);
            if (sm_list < 0)
                goto end;
        }
    } else {
        sm_list = DETECT_SM_LIST_PMATCH;
    }

    if (offset != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(offset, s, &index)) {
            SCLogError("Unknown byte_extract var "
                       "seen in isdataat - %s\n",
                    offset);
            goto end;
        }
        idad->dataat = index;
        idad->flags |= ISDATAAT_OFFSET_VAR;
        SCLogDebug("isdataat uses byte_extract with local id %u", idad->dataat);
        SCFree(offset);
        offset = NULL;
    }

    /* 'ends with' scenario */
    if (prev_pm != NULL && prev_pm->type == DETECT_CONTENT &&
        idad->dataat == 1 &&
        (idad->flags & (ISDATAAT_RELATIVE|ISDATAAT_NEGATED)) == (ISDATAAT_RELATIVE|ISDATAAT_NEGATED))
    {
        DetectIsdataatFree(de_ctx, idad);
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        cd->flags |= DETECT_CONTENT_ENDS_WITH;
        ret = 0;
        goto end;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ISDATAAT, (SigMatchCtx *)idad, sm_list) == NULL) {
        goto end;
    }

    if (!(idad->flags & ISDATAAT_RELATIVE)) {
        ret = 0;
        goto end;
    }

    if (prev_pm == NULL) {
        ret = 0;
        goto end;
    }

    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *pd = (DetectPcreData *)prev_pm->ctx;
        pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

    ret = 0;

end:
    if (offset)
        SCFree(offset);
    if (ret != 0)
        DetectIsdataatFree(de_ctx, idad);
    return ret;
}

/**
 * \brief this function will free memory associated with DetectIsdataatData
 *
 * \param idad pointer to DetectIsdataatData
 */
void DetectIsdataatFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIsdataatData *idad = (DetectIsdataatData *)ptr;
    SCFree(idad);
}

static int DetectEndsWithSetup (DetectEngineCtx *de_ctx, Signature *s, const char *nullstr)
{
    SigMatch *pm = NULL;
    int ret = -1;

    /* retrieve the sm to apply the depth against */
    pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, -1);
    if (pm == NULL) {
        SCLogError("endswith needs a "
                   "preceding content option");
        goto end;
    }

    /* verify other conditions. */
    DetectContentData *cd = (DetectContentData *)pm->ctx;

    cd->flags |= DETECT_CONTENT_ENDS_WITH;

    ret = 0;
 end:
    return ret;
}

#ifdef UNITTESTS
static int g_dce_stub_data_buffer_id = 0;

/**
 * \test DetectIsdataatTestParse01 is a test to make sure that we return a correct IsdataatData structure
 *  when given valid isdataat opt
 */
static int DetectIsdataatTestParse01 (void)
{
    int result = 0;
    DetectIsdataatData *idad = NULL;
    idad = DetectIsdataatParse(NULL, "30 ", NULL);
    if (idad != NULL) {
        DetectIsdataatFree(NULL, idad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectIsdataatTestParse02 is a test to make sure that we return a correct IsdataatData structure
 *  when given valid isdataat opt
 */
static int DetectIsdataatTestParse02 (void)
{
    int result = 0;
    DetectIsdataatData *idad = NULL;
    idad = DetectIsdataatParse(NULL, "30 , relative", NULL);
    if (idad != NULL && idad->flags & ISDATAAT_RELATIVE && !(idad->flags & ISDATAAT_RAWBYTES)) {
        DetectIsdataatFree(NULL, idad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectIsdataatTestParse03 is a test to make sure that we return a correct IsdataatData structure
 *  when given valid isdataat opt
 */
static int DetectIsdataatTestParse03 (void)
{
    int result = 0;
    DetectIsdataatData *idad = NULL;
    idad = DetectIsdataatParse(NULL, "30,relative, rawbytes ", NULL);
    if (idad != NULL && idad->flags & ISDATAAT_RELATIVE && idad->flags & ISDATAAT_RAWBYTES) {
        DetectIsdataatFree(NULL, idad);
        result = 1;
    }

    return result;
}

/**
 * \test Test isdataat option for dce sig.
 */
static int DetectIsdataatTestParse04(void)
{
    Signature *s = SigAlloc();
    FAIL_IF_NULL(s);

    FAIL_IF(DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0);

    FAIL_IF_NOT(DetectIsdataatSetup(NULL, s, "30") == 0);
    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NOT_NULL(sm);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_PMATCH]);
    SigFree(NULL, s);

    s = SigAlloc();
    FAIL_IF_NULL(s);
    FAIL_IF(DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0);
    /* relative w/o preceeding match defaults to "pmatch" */
    FAIL_IF_NOT(DetectIsdataatSetup(NULL, s, "30,relative") == 0);
    sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NOT_NULL(sm);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_PMATCH]);

    SigFree(NULL, s);
    PASS;
}

static int DetectIsdataatTestParse06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytejump_body\"; "
                               "content:\"one\"; "
                               "isdataat:!4,relative; sid:1;)");
    FAIL_IF(s == NULL);

    FAIL_IF(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL);

    FAIL_IF_NOT(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]->type == DETECT_ISDATAAT);
    DetectIsdataatData *data =
            (DetectIsdataatData *)s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]->ctx;

    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytejump_body\"; "
                               "content:\"one\"; "
                               "isdataat: !4,relative; sid:2;)");
    FAIL_IF(s == NULL);

    FAIL_IF(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL);

    FAIL_IF_NOT(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]->type == DETECT_ISDATAAT);
    data = (DetectIsdataatData *)s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]->ctx;

    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectIsdataatTestPacket01 is a test to check matches of
 * isdataat, and isdataat relative
 */
static int DetectIsdataatTestPacket01 (void)
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

    const char *sigs[5];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing window 1\"; isdataat:6; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing window 2\"; content:\"all\"; isdataat:1, relative; isdataat:6; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing window 3\"; isdataat:8; sid:3;)";
    sigs[3]= "alert ip any any -> any any (msg:\"Testing window 4\"; content:\"Hi\"; isdataat:5, relative; sid:4;)";
    sigs[4]= "alert ip any any -> any any (msg:\"Testing window 4\"; content:\"Hi\"; isdataat:6, relative; sid:5;)";

    uint32_t sid[5] = {1, 2, 3, 4, 5};

    uint32_t results[3][5] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {1, 1, 0, 1, 0},
                              /* packet 1 should not match */
                              {1, 1, 0, 1, 0},
                              /* packet 2 should not match */
                              {1, 1, 0, 1, 0} };

    result = UTHGenericTest(p, 3, sigs, sid, (uint32_t *) results, 5);

    UTHFreePackets(p, 3);
end:
    return result;
}

/**
 * \test DetectIsdataatTestPacket02 is a test to check matches of
 * isdataat, and isdataat relative works if the previous keyword is pcre
 * (bug 144)
 */
static int DetectIsdataatTestPacket02 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre with"
            " isdataat + relative\"; pcre:\"/A(ll|pp)WorkAndNoPlayMakesWillA"
            "DullBoy/\"; isdataat:96,relative; sid:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}

/**
 * \test DetectIsdataatTestPacket03 is a test to check matches of
 * isdataat, and isdataat relative works if the previous keyword is byte_jump
 * (bug 146)
 */
static int DetectIsdataatTestPacket03 (void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"byte_jump match = 0 "
    "with distance content HTTP/1. relative against HTTP/1.0\"; byte_jump:1,"
    "46,string,dec; isdataat:87,relative; sid:109; rev:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}

/**
 * \brief this function registers unit tests for DetectIsdataat
 */
void DetectIsdataatRegisterTests(void)
{
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

    UtRegisterTest("DetectIsdataatTestParse01", DetectIsdataatTestParse01);
    UtRegisterTest("DetectIsdataatTestParse02", DetectIsdataatTestParse02);
    UtRegisterTest("DetectIsdataatTestParse03", DetectIsdataatTestParse03);
    UtRegisterTest("DetectIsdataatTestParse04", DetectIsdataatTestParse04);
    UtRegisterTest("DetectIsdataatTestParse06", DetectIsdataatTestParse06);

    UtRegisterTest("DetectIsdataatTestPacket01", DetectIsdataatTestPacket01);
    UtRegisterTest("DetectIsdataatTestPacket02", DetectIsdataatTestPacket02);
    UtRegisterTest("DetectIsdataatTestPacket03", DetectIsdataatTestPacket03);
}

static int DetectAbsentTestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any "
            "(msg:\"invalid absent only with negated content\"; http.user_agent; "
            "absent; content:!\"one\"; sid:2;)");
    FAIL_IF(s != NULL);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                      "(msg:\"invalid absent\"; http.user_agent; "
                                      "content:!\"one\"; absent; sid:2;)");
    FAIL_IF(s != NULL);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                      "(msg:\"invalid absent\"; http.user_agent; "
                                      "content:\"one\"; absent: or_else; sid:2;)");
    FAIL_IF(s != NULL);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                      "(msg:\"absent without sticky buffer\"; "
                                      "content:!\"one\"; absent: or_else; sid:2;)");
    FAIL_IF(s != NULL);
    s = DetectEngineAppendSig(de_ctx,
            "alert websocket any any -> any any "
            "(msg:\"absent with frame\"; "
            "frame: websocket.pdu; absent: or_else; content:!\"one\"; sid:2;)");
    FAIL_IF(s != NULL);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectAbsentRegisterTests(void)
{
    UtRegisterTest("DetectAbsentTestParse01", DetectAbsentTestParse01);
}
#endif
