/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file detect-icmp-id.c
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 * "icmp_id" keyword support
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-icmp-id.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(\"\\s*)?([0-9]+)(\\s*\")?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectIcmpIdMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectIcmpIdSetup(DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectIcmpIdRegisterTests(void);
void DetectIcmpIdFree(void *);

/**
 * \brief Registration function for icode: icmp_id
 */
void DetectIcmpIdRegister (void) {
    sigmatch_table[DETECT_ICMP_ID].name = "icmp_id";
    sigmatch_table[DETECT_ICMP_ID].Match = DetectIcmpIdMatch;
    sigmatch_table[DETECT_ICMP_ID].Setup = DetectIcmpIdSetup;
    sigmatch_table[DETECT_ICMP_ID].Free = DetectIcmpIdFree;
    sigmatch_table[DETECT_ICMP_ID].RegisterTests = DetectIcmpIdRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogDebug("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogDebug("pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    return;
}

/**
 * \brief This function is used to match icmp_id rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectIcmpIdData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectIcmpIdMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m) {
    uint16_t pid;
    DetectIcmpIdData *iid = (DetectIcmpIdData *)m->ctx;

    if (PKT_IS_ICMPV4(p)) {
        switch (ICMPV4_GET_TYPE(p)){
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TIMESTAMP:
            case ICMP_TIMESTAMPREPLY:
            case ICMP_INFO_REQUEST:
            case ICMP_INFO_REPLY:
            case ICMP_ADDRESS:
            case ICMP_ADDRESSREPLY:
                pid = ICMPV4_GET_ID(p);
                break;
            default:
                SCLogDebug("Packet has no id field");
                return 0;
        }
    } else if (PKT_IS_ICMPV6(p)) {
        switch (ICMPV6_GET_TYPE(p)) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
                pid = ICMPV6_GET_ID(p);
                break;
            default:
                SCLogDebug("Packet has no id field");
                return 0;
        }
    } else {
        SCLogDebug("Packet not ICMPV4 nor ICMPV6");
        return 0;
    }

    if (pid == iid->id) return 1;

    return 0;
}

/**
 * \brief This function is used to parse icmp_id option passed via icmp_id: keyword
 *
 * \param icmpidstr Pointer to the user provided icmp_id options
 *
 * \retval iid pointer to DetectIcmpIdData on success
 * \retval NULL on failure
 */
DetectIcmpIdData *DetectIcmpIdParse (char *icmpidstr) {
    DetectIcmpIdData *iid = NULL;
    char *substr[3] = {NULL, NULL, NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, icmpidstr, strlen(icmpidstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogDebug("DetectIcmpIdParse: parse error, ret %" PRId32 ", string %s\n", ret, icmpidstr);
        goto error;
    }

    int i;
    const char *str_ptr;
    for (i = 1; i < ret; i++) {
        res = pcre_get_substring((char *)icmpidstr, ov, MAX_SUBSTRINGS, i, &str_ptr);
        if (res < 0) {
            SCLogDebug("DetectIcmpIdParse: pcre_get_substring failed");
            goto error;
        }
        substr[i-1] = (char *)str_ptr;
    }

    iid = malloc(sizeof(DetectIcmpIdData));
    if (iid == NULL) {
        SCLogDebug("DetectIcmpIdParse: malloc failed");
        goto error;
    }
    iid->id = 0;

    if (strlen(substr[0]) != 0) {
        if (substr[2] == NULL) {
            SCLogDebug("DetectIcmpIdParse: Missing close quote in input");
            goto error;
        }
    } else {
        if (substr[2] != NULL) {
            SCLogDebug("DetectIcmpIdParse: Missing open quote in input");
            goto error;
        }
    }
    ByteExtractStringUint16(&iid->id, 10, 0, substr[1]);

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) free(substr[i]);
    }
    return iid;

error:
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) free(substr[i]);
    }
    if (iid != NULL) DetectIcmpIdFree(iid);
    return NULL;

}

/**
 * \brief this function is used to add the parsed icmp_id data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param icmpidstr pointer to the user provided icmp_id option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectIcmpIdSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *icmpidstr) {
    DetectIcmpIdData *iid = NULL;
    SigMatch *sm = NULL;

    iid = DetectIcmpIdParse(icmpidstr);
    if (iid == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ICMP_ID;
    sm->ctx = (void *)iid;

    SigMatchAppend(s, m, sm);

    return 0;

error:
    if (iid != NULL) DetectIcmpIdFree(iid);
    if (sm != NULL) free(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIcmpIdData
 *
 * \param ptr pointer to DetectIcmpIdData
 */
void DetectIcmpIdFree (void *ptr) {
    DetectIcmpIdData *iid = (DetectIcmpIdData *)ptr;
    free(iid);
}

#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectIcmpIdParseTest01 is a test for setting a valid icmp_id value
 */
int DetectIcmpIdParseTest01 (void) {
    DetectIcmpIdData *iid = NULL;
    iid = DetectIcmpIdParse("300");
    if (iid != NULL && iid->id == 300) {
        DetectIcmpIdFree(iid);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpIdParseTest02 is a test for setting a valid icmp_id value
 *       with spaces all around
 */
int DetectIcmpIdParseTest02 (void) {
    DetectIcmpIdData *iid = NULL;
    iid = DetectIcmpIdParse("  300  ");
    if (iid != NULL && iid->id == 300) {
        DetectIcmpIdFree(iid);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpIdParseTest03 is a test for setting a valid icmp_id value
 *       with quotation marks
 */
int DetectIcmpIdParseTest03 (void) {
    DetectIcmpIdData *iid = NULL;
    iid = DetectIcmpIdParse("\"300\"");
    if (iid != NULL && iid->id == 300) {
        DetectIcmpIdFree(iid);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpIdParseTest04 is a test for setting a valid icmp_id value
 *       with quotation marks and spaces all around
 */
int DetectIcmpIdParseTest04 (void) {
    DetectIcmpIdData *iid = NULL;
    iid = DetectIcmpIdParse("   \"   300 \"");
    if (iid != NULL && iid->id == 300) {
        DetectIcmpIdFree(iid);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpIdParseTest05 is a test for setting an invalid icmp_id
 *       value with missing quotation marks
 */
int DetectIcmpIdParseTest05 (void) {
    DetectIcmpIdData *iid = NULL;
    iid = DetectIcmpIdParse("\"300");
    if (iid == NULL) {
        DetectIcmpIdFree(iid);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpIdMatchTest01 is a test for checking the working of
 *       icmp_id keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
int DetectIcmpIdMatchTest01 (void) {
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x08, 0x00, 0x64, 0x03, 0x55, 0x15, 0x00, 0x00,
        0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
        0x58 };

    Packet p;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

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

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:5461; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:5000; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1) == 0) {
        printf("sid 1 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(&p, 2)) {
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
    return result;

}

/**
 * \test DetectIcmpIdMatchTest02 is a test for checking the working of
 *       icmp_id keyword by creating 1 rule and matching a crafted packet
 *       against them. The packet is an ICMP packet with no "id" field,
 *       therefore the rule should not trigger.
 */
int DetectIcmpIdMatchTest02 (void) {
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x0b, 0x00, 0x8a, 0xdf, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x00, 0x00, 0x14, 0x25, 0x0c, 0x00, 0x00,
        0xff, 0x11, 0x00, 0x00, 0x85, 0x64, 0xea, 0x5b,
        0x51, 0xa6, 0xbb, 0x35, 0x59, 0x8a, 0x5a, 0xe2,
        0x00, 0x14, 0x00, 0x00 };

    Packet p;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

    memset(&p, 0, sizeof(Packet));
    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

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

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:0; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)) {
        printf("sid 1 alerted, but should not have: ");
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
    return result;
}
#endif /* UNITTESTS */

void DetectIcmpIdRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectIcmpIdParseTest01", DetectIcmpIdParseTest01, 1);
    UtRegisterTest("DetectIcmpIdParseTest02", DetectIcmpIdParseTest02, 1);
    UtRegisterTest("DetectIcmpIdParseTest03", DetectIcmpIdParseTest03, 1);
    UtRegisterTest("DetectIcmpIdParseTest04", DetectIcmpIdParseTest04, 1);
    UtRegisterTest("DetectIcmpIdParseTest05", DetectIcmpIdParseTest05, 1);
    UtRegisterTest("DetectIcmpIdMatchTest01", DetectIcmpIdMatchTest01, 1);
    UtRegisterTest("DetectIcmpIdMatchTest02", DetectIcmpIdMatchTest02, 1);
#endif /* UNITTESTS */
}

