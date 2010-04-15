/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "decode-events.h"
#include "stream-tcp.h"

#include "detect-reference.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(cve|nessus|url|mcafee|bugtraq|arachnids)\\s*,\\s*([a-zA-Z0-9\\-_\\.\\/\\?\\=]+)\\s*"

/* Static prefix for references - Maybe we should move them to reference.config in the future */
char REFERENCE_BUGTRAQ[] =   "http://www.securityfocus.com/bid/";
char REFERENCE_CVE[] =       "http://cve.mitre.org/cgi-bin/cvename.cgi?name=";
char REFERENCE_NESSUS[] =    "http://cgi.nessus.org/plugins/dump.php3?id=";
char REFERENCE_ARACHNIDS[] = "http://www.whitehats.com/info/IDS";
char REFERENCE_MCAFEE[] =    "http://vil.nai.com/vil/dispVirus.asp?virus_k=";
char REFERENCE_URL[] =       "http://";

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectReferenceSetup (DetectEngineCtx *, Signature *s, char *str);

/**
 * \brief Registration function for reference: keyword
 */

void DetectReferenceRegister (void) {
    sigmatch_table[DETECT_REFERENCE].name = "reference";
    sigmatch_table[DETECT_REFERENCE].Match = NULL;
    sigmatch_table[DETECT_REFERENCE].Setup = DetectReferenceSetup;
    sigmatch_table[DETECT_REFERENCE].Free  = NULL;
    sigmatch_table[DETECT_REFERENCE].RegisterTests = ReferenceRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    return;

}

/**
 * \internal
 * \brief This function is used to parse reference options passed via reference: keyword
 *
 * \param rawstr Pointer to the user provided reference options
 *
 * \retval sigref pointer to signature reference on success
 * \retval NULL on failure
 */
static char *DetectReferenceParse (char *rawstr)
{
    DetectReferenceData *ref = NULL;
    char *sigref = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *ref_key = NULL;
    const char *ref_content = NULL;
    int sig_len = 0;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    ref = SCMalloc(sizeof(DetectReferenceData));
    if (ref == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }

    memset(ref,0,sizeof(DetectReferenceData));

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,1, &ref_key);

    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,2, &ref_content);

    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    if (ref_key == NULL || ref_content == NULL)
        goto error;

    if (strcasecmp(ref_key,"cve") == 0)  {
        ref->reference = REFERENCE_CVE;
    } else if (strcasecmp(ref_key,"bugtraq") == 0) {
        ref->reference = REFERENCE_BUGTRAQ;
    } else if (strcasecmp(ref_key,"nessus") == 0) {
        ref->reference = REFERENCE_NESSUS;
    } else if (strcasecmp(ref_key,"url") == 0) {
        ref->reference = REFERENCE_URL;
    } else if (strcasecmp(ref_key,"mcafee") == 0) {
        ref->reference = REFERENCE_MCAFEE;
    } else if (strcasecmp(ref_key,"arachnids") == 0) {
        ref->reference = REFERENCE_ARACHNIDS;
    }

    sig_len = (strlen(ref->reference) + strlen(ref_content)+1);

    sigref = SCMalloc(sig_len+1);
    if (sigref == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }

    memset(sigref,0,sig_len);

    strlcpy(sigref,ref->reference,strlen(ref->reference)+1);
    strlcat(sigref,ref_content,sig_len);

    sigref[strlen(sigref)] = '\0';

    if (ref) SCFree(ref);
    if (ref_key) SCFree((char *)ref_key);
    if (ref_content) SCFree((char *)ref_content);
    return sigref;

error:

    if (ref_key) SCFree((char *)ref_key);
    if (ref_content) SCFree((char *)ref_content);
    if (ref) SCFree(ref);

    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed reference into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided reference options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectReferenceSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    char *ref = NULL;
    References *sref = NULL;
    References *actual_reference = NULL;

    ref = DetectReferenceParse(rawstr);
    if (ref == NULL)
        goto error;

    if(s->sigref == NULL)  {

        s->sigref = SCMalloc(sizeof(References));
        if (s->sigref == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
            goto error;
        }

        s->sigref->reference = ref;
        s->sigref->next = NULL;

    } else {

        sref = SCMalloc(sizeof(References));
        if (sref == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
            goto error;
        }

        sref->reference = ref;
        sref->next = NULL;

        actual_reference = s->sigref;

        while (actual_reference->next != NULL)    {
            actual_reference = actual_reference->next;
        }

        actual_reference->next = sref;
    }

    return 0;

error:
    if (ref) SCFree(ref);
    if (sref) SCFree(sref);
    return -1;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS

/**
 * \test DetectReferenceParseTest01 is a test for one valid reference.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectReferenceParseTest01(void)
{
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x42, 0xb4, 0x02, 0x00, 0x08, 0xa8,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    Packet p;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;
    References *sref = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.src.addr_data32[0] = 0x01020304;
    p.dst.addr_data32[0] = 0x04030201;

    ip4h.ip_src.s_addr = p.src.addr_data32[0];
    ip4h.ip_dst.s_addr = p.dst.addr_data32[0];
    p.ip4h = &ip4h;

    DecodeICMPV4(&th_v, &dtv, &p, raw_icmpv4, sizeof(raw_icmpv4), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"One reference\"; reference:cve,001-2010; sid:2;)");

    if (s == NULL) {
        goto end;
    }

    if (s->sigref == NULL)  {
        goto cleanup;
    }

    for (sref = s->sigref; sref != NULL; sref = sref->next) {
        if (strcmp(sref->reference,"http://cve.mitre.org/cgi-bin/cvename.cgi?name=001-2010") != 0)  {
            goto cleanup;
        }
    }

    result = 1;

cleanup:
    if (s) SigFree(s);
    if (det_ctx) DetectEngineCtxFree(de_ctx);

    FlowShutdown();
end:
    return result;

}

/**
 * \test DetectReferenceParseTest02 is a test for two valid references.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectReferenceParseTest02(void)
{
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x42, 0xb4, 0x02, 0x00, 0x08, 0xa8,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    Packet p;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;
    References *sref = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.src.addr_data32[0] = 0x01020304;
    p.dst.addr_data32[0] = 0x04030201;

    ip4h.ip_src.s_addr = p.src.addr_data32[0];
    ip4h.ip_dst.s_addr = p.dst.addr_data32[0];
    p.ip4h = &ip4h;

    DecodeICMPV4(&th_v, &dtv, &p, raw_icmpv4, sizeof(raw_icmpv4), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"Two references\"; reference:url,www.openinfosecfoundation.org; reference:cve,001-2010; sid:2;)");

    if (s == NULL) {
        goto end;
    }

    if (s->sigref == NULL)  {
        goto cleanup;
    }

    for (sref = s->sigref; sref != NULL; sref = sref->next) {

        if (strcmp(sref->reference,"http://www.openinfosecfoundation.org") == 0)  {
            result++;
        }

        if (strcmp(sref->reference,"http://cve.mitre.org/cgi-bin/cvename.cgi?name=001-2010") == 0)  {
            result++;
        }
    }

    if (result == 2)    {
        result = 1;
    }

cleanup:
    if (s) SigFree(s);
    if (det_ctx) DetectEngineCtxFree(de_ctx);

    FlowShutdown();
end:
    return result;

}

/**
 * \test DetectReferenceParseTest03 is a test for one invalid reference.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectReferenceParseTest03(void)
{
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x42, 0xb4, 0x02, 0x00, 0x08, 0xa8,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61,
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
    Packet p;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;
    References *sref = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.src.addr_data32[0] = 0x01020304;
    p.dst.addr_data32[0] = 0x04030201;

    ip4h.ip_src.s_addr = p.src.addr_data32[0];
    ip4h.ip_dst.s_addr = p.dst.addr_data32[0];
    p.ip4h = &ip4h;

    DecodeICMPV4(&th_v, &dtv, &p, raw_icmpv4, sizeof(raw_icmpv4), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (msg:\"Two references\"; reference:url,www.openinfosecfoundation.org; reference:oisf,001-2010; sid:2;)");

    if (s == NULL) {
        goto end;
    }

    if (s->sigref == NULL)  {
        goto cleanup;
    }

    for (sref = s->sigref; sref != NULL; sref = sref->next) {
        result++;
    }

cleanup:
    if (s) SigFree(s);
    if (det_ctx) DetectEngineCtxFree(de_ctx);

    FlowShutdown();
end:
    return result;

}
#endif /* UNITTESTS */

void ReferenceRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectReferenceParseTest01", DetectReferenceParseTest01, 1);
    UtRegisterTest("DetectReferenceParseTest02", DetectReferenceParseTest02, 1);
    UtRegisterTest("DetectReferenceParseTest03", DetectReferenceParseTest03, 0);
#endif /* UNITTESTS */
}
