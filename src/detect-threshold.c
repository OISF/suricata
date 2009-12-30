/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "decode-events.h"
#include "stream-tcp.h"

#include "detect-threshold.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*type\\s+(limit|both|threshold)\\s*,\\s*track\\s+(by_src|by_dst)\\s*,\\s*count\\s+(\\d+)\\s*,\\s*seconds\\s+(\\d+)\\s*"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectThresholdMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectThresholdSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);
static void DetectThresholdFree(void *);

/**
 * \brief Registration function for threshold: keyword
 */

void DetectThresholdRegister (void) {
    sigmatch_table[DETECT_THRESHOLD].name = "threshold";
    sigmatch_table[DETECT_THRESHOLD].Match = DetectThresholdMatch;
    sigmatch_table[DETECT_THRESHOLD].Setup = DetectThresholdSetup;
    sigmatch_table[DETECT_THRESHOLD].Free  = DetectThresholdFree;
    sigmatch_table[DETECT_THRESHOLD].RegisterTests = ThresholdRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        goto error;
    }

error:
    return;

}

static int DetectThresholdMatch (ThreadVars *thv, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *sm)
{
    return 1;
}

/**
 * \internal
 * \brief This function is used to parse threshold options passed via threshold: keyword
 *
 * \param rawstr Pointer to the user provided threshold options
 *
 * \retval de pointer to DetectThresholdData on success
 * \retval NULL on failure
 */
static DetectThresholdData *DetectThresholdParse (char *rawstr)
{
    DetectThresholdData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr = NULL;
    char *args[4] = { NULL, NULL, NULL, NULL };
    int i;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 5)
        goto error;

    de = malloc(sizeof(DetectThresholdData));
    if (de == NULL) {
        printf("DetectThresholdSetup malloc failed\n");
        goto error;
    }

    memset(de,0,sizeof(DetectThresholdData));

    for (i = 0; i < (ret - 1); i++) {

        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,i + 1, &str_ptr);

        if (res < 0)
            goto error;

        args[i] = (char *)str_ptr;

        if (strncasecmp(args[i],"limit",strlen("limit")) == 0)
            de->type = TYPE_LIMIT;
        if (strncasecmp(args[i],"both",strlen("both")) == 0)
            de->type = TYPE_BOTH;
        if (strncasecmp(args[i],"threshold",strlen("threshold")) == 0)
            de->type = TYPE_THRESHOLD;
        if (strncasecmp(args[i],"by_dst",strlen("by_dst")) == 0)
            de->track = TRACK_DST;
        if (strncasecmp(args[i],"by_src",strlen("by_src")) == 0)
            de->track = TRACK_SRC;
    }

    if (ByteExtractStringUint32(&de->count, 10, strlen(args[2]), args[2]) <= 0) {
        goto error;
    }

    if (ByteExtractStringUint32(&de->seconds, 10, strlen(args[3]), args[3]) <= 0) {
        goto error;
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    return de;

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    if (de) free(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed threshold into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided threshold options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectThresholdSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    DetectThresholdData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectThresholdParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_THRESHOLD;
    sm->ctx = (void *)de;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (de) free(de);
    if (sm) free(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectThresholdData
 *
 * \param de pointer to DetectThresholdData
 */
static void DetectThresholdFree(void *de_ptr) {
    DetectThresholdData *de = (DetectThresholdData *)de_ptr;
    if (de) free(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-threshold.h"
#include "util-time.h"
#include "util-hashlist.h"

/**
 * \test ThresholdTestParse01 is a test for a valid threshold options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int ThresholdTestParse01 (void) {
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("type limit,track by_dst,count 10,seconds 60");
    if (de && (de->type == TYPE_LIMIT) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test ThresholdTestParse02 is a test for a invalid threshold options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int ThresholdTestParse02 (void) {
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("type any,track by_dst,count 10,seconds 60");
    if (de && (de->type == TYPE_LIMIT) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test DetectThresholdTestSig1 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig1(void) {

    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&ip4h, 0, sizeof(ip4h));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.ip4h = &ip4h;
    p.ip4h->ip_src.s_addr = 0x01010101;
    p.ip4h->ip_dst.s_addr = 0x02020202;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    alerts = PacketAlertCheck(&p, 1);

    if(alerts == 5)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

/**
 * \test DetectThresholdTestSig2 is a test for checking the working of threshold keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig2(void) {

    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&ip4h, 0, sizeof(ip4h));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.ip4h = &ip4h;
    p.ip4h->ip_src.s_addr = 0x01010101;
    p.ip4h->ip_dst.s_addr = 0x02020202;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold\"; threshold: type threshold, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    alerts = PacketAlertCheck(&p, 1);

    if (alerts == 2)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

/**
 * \test DetectThresholdTestSig3 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig3(void) {

    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    IPV4Hdr ip4h;
    struct timeval ts;
    DetectThresholdData *td = NULL;
    DetectThresholdEntry *lookup_tsh = NULL;
    DetectThresholdEntry *ste = NULL;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&ip4h, 0, sizeof(ip4h));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.ip4h = &ip4h;
    p.ip4h->ip_src.s_addr = 0x01010101;
    p.ip4h->ip_dst.s_addr = 0x02020202;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    td = SigGetThresholdType(s,&p);

    /* setup the Entry we use to search our hash with */
    ste = malloc(sizeof(DetectThresholdEntry));
    if (ste == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed: %s", strerror(errno));
        goto end;
    }
    memset(ste, 0x00, sizeof(ste));

    if (PKT_IS_IPV4(&p))
        ste->ipv = 4;
    else if (PKT_IS_IPV6(&p))
        ste->ipv = 6;

    ste->sid = s->id;
    ste->gid = s->gid;

    if (td->track == TRACK_DST) {
        COPY_ADDRESS(&p.dst, &ste->addr);
    } else if (td->track == TRACK_SRC) {
        COPY_ADDRESS(&p.src, &ste->addr);
    }

    ste->track = td->track;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    lookup_tsh = (DetectThresholdEntry *)HashListTableLookup(de_ctx->ths_ctx.threshold_hash_table_dst, ste, sizeof(DetectThresholdEntry));
    if (lookup_tsh == NULL) {
        printf("lookup_tsh is NULL: ");
        goto cleanup;
    }

    TimeSetIncrementTime(200);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (lookup_tsh)
        alerts = lookup_tsh->current_count;

    if (alerts == 3)
        result = 1;
    else {
        printf("alerts %u != 3: ", alerts);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectThresholdTestSig4 is a test for checking the working of both keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig4(void) {

    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    IPV4Hdr ip4h;
    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&ip4h, 0, sizeof(ip4h));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.ip4h = &ip4h;
    p.ip4h->ip_src.s_addr = 0x01010101;
    p.ip4h->ip_dst.s_addr = 0x02020202;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold both\"; threshold: type both, track by_dst, count 2, seconds 60; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    TimeSetIncrementTime(200);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    alerts = PacketAlertCheck(&p, 10);

    if (alerts == 2)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

/**
 * \test DetectThresholdTestSig5 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig5(void) {

    Packet p;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&ip4h, 0, sizeof(ip4h));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.proto = IPPROTO_TCP;
    p.ip4h = &ip4h;
    p.ip4h->ip_src.s_addr = 0x01010101;
    p.ip4h->ip_dst.s_addr = 0x02020202;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit sid 1\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit sid 1000\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    alerts = PacketAlertCheck(&p, 1);

    alerts += PacketAlertCheck(&p, 1000);

    if(alerts == 10)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}
#endif /* UNITTESTS */

void ThresholdRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("ThresholdTestParse01", ThresholdTestParse01, 1);
    UtRegisterTest("ThresholdTestParse02", ThresholdTestParse02, 0);
    UtRegisterTest("DetectThresholdTestSig1", DetectThresholdTestSig1, 1);
    UtRegisterTest("DetectThresholdTestSig2", DetectThresholdTestSig2, 1);
    UtRegisterTest("DetectThresholdTestSig3", DetectThresholdTestSig3, 1);
    UtRegisterTest("DetectThresholdTestSig4", DetectThresholdTestSig4, 1);
    UtRegisterTest("DetectThresholdTestSig5", DetectThresholdTestSig5, 1);
#endif /* UNITTESTS */
}
