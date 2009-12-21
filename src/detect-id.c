/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \file detect-id.c
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * "id" keyword, IPv4 Identifier keyword, part of the detection engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-id.h"
#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */
#define PARSE_REGEX  "^\\s*([0-9]{1,5}|\"[0-9]{1,5}\")\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectIdMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
                    Signature *, SigMatch *);
int DetectIdSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectIdRegisterTests(void);
void DetectIdFree(void *);

/**
 * \brief Registration function for keyword: id
 */
void DetectIdRegister (void) {
    sigmatch_table[DETECT_ID].name = "id";
    sigmatch_table[DETECT_ID].Match = DetectIdMatch;
    sigmatch_table[DETECT_ID].Setup = DetectIdSetup;
    sigmatch_table[DETECT_ID].Free  = DetectIdFree;
    sigmatch_table[DETECT_ID].RegisterTests = DetectIdRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

	SCLogDebug("detect-id: Registering id rule option\n");

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogDebug("Compile of \"%s\" failed at offset %" PRId32 ": %s\n",
                    PARSE_REGEX, eo, eb);
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
int DetectIdMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                        Signature *s, SigMatch *m)
{
    DetectIdData *id_d = (DetectIdData *)m->ctx;

    /**
     * To match a ipv4 packet with a "id" rule
     */
    if (!PKT_IS_IPV4(p)) {
        return 0;
    }

    if (id_d->id == IPV4_GET_IPID(p)) {
        SCLogDebug("detect-id: IPV4 Proto and matched with ip_id: %u.\n",
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
DetectIdData *DetectIdParse (char *idstr)
{
    uint32_t temp;
    DetectIdData *id_d = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];


    ret = pcre_exec(parse_regex, parse_regex_study, idstr, strlen(idstr), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogDebug("detect-id: invalid id option. The id option value must be"
                    " in the range %u - %u\n",
                    DETECT_IPID_MIN, DETECT_IPID_MAX);
        goto error;
    }


    if (ret > 1) {
        const char *str_ptr;
        char *orig;
        char *tmp_str;
        res = pcre_get_substring((char *)idstr, ov, MAX_SUBSTRINGS, 1,
                                    &str_ptr);
        if (res < 0) {
            SCLogDebug("DetectIdParse: pcre_get_substring failed\n");
            goto error;
        }

        /* We have a correct id option */
        id_d = malloc(sizeof(DetectIdData));
        if (id_d == NULL) {
            SCLogDebug("DetectIdParse malloc failed\n");
            goto error;
        }

        orig = strdup((char*)str_ptr);
        tmp_str=orig;
        /* Let's see if we need to scape "'s */
        if (tmp_str[0] == '"')
        {
            tmp_str[strlen(tmp_str) - 1] = '\0';
            tmp_str += 1;
        }

        /* ok, fill the id data */
        temp = atoi((char *)tmp_str);

        if (temp > DETECT_IPID_MAX || temp < DETECT_IPID_MIN) {
            SCLogDebug("detect-id: \"id\" option  must be in "
                        "the range %u - %u\n",
                        DETECT_IPID_MIN, DETECT_IPID_MAX);

            free(orig);
            goto error;
        }
        id_d->id = temp;

        free(orig);

        SCLogDebug("detect-id: will look for ip_id: %u\n", id_d->id);
    }

    return id_d;

error:
    if (id_d != NULL) DetectIdFree(id_d);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectIdSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                    char *idstr)
{
    DetectIdData *id_d = NULL;
    SigMatch *sm = NULL;

    id_d = DetectIdParse(idstr);
    if (id_d == NULL) goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ID;
    sm->ctx = (void *)id_d;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (id_d != NULL) DetectIdFree(id_d);
    if (sm != NULL) free(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIdData
 *
 * \param id_d pointer to DetectIdData
 */
void DetectIdFree(void *ptr) {
    DetectIdData *id_d = (DetectIdData *)ptr;
    free(id_d);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectIdTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
int DetectIdTestParse01 (void) {
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
int DetectIdTestParse02 (void) {
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
int DetectIdTestParse03 (void) {
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
int DetectIdTestParse04 (void) {
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
 * \test DetectIdTestPacket01 is a test to check "id" option with constructed
 *       packets, expecting to match
 *       Parse Id Data: expecting ip_id == 41158
 *       The packet has ip_id == 41158 so it must match
 */
int DetectIdTestPacket01 (void) {
    DetectIdData *id_d = NULL;

    id_d = DetectIdParse(" 41158");
    if (id_d == NULL) {
        SCLogDebug("DetectIdTestPacket01: expected a DetectIdData pointer"
                   " (got NULL)\n");
        return 0;
    }
    /* Buid and decode the packet */
    uint8_t raw_eth [] = {
        0x00, 0x14, 0xf8, 0x50, 0xf9, 0x09, 0x00, 0x10,
        0xdc, 0x4f, 0xe6, 0x09, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0xa0, 0xc6, 0x40, 0x00, 0x40, 0x06,
        0xab, 0x46, 0xc0, 0xa8, 0x00, 0xdc, 0x4b, 0x7d,
        0xe1, 0xad, 0xbe, 0x23, 0x00, 0x50, 0xf4, 0x66,
        0x71, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x45, 0xf0, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x06, 0xae,
        0xd1, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06 };

    Packet q;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&q, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&tv, &dtv, &q, raw_eth, sizeof(raw_eth), NULL);
    FlowShutdown();

    Packet *p=&q;

    if (!(PKT_IS_IPV4(p))) {
        SCLogDebug("detect-id: TestPacket01: Packet is not IPV4\n");
        return 0;
    }

    DetectEngineThreadCtx *det_ctx=NULL;
    Signature *s=NULL;

    SigMatch m;
    m.ctx=id_d;

    /* Now that we have what we need, just try to Match! */
    return DetectIdMatch (&tv, det_ctx, p, s, &m);
}

/**
 * \test DetectIdTestPacket02 is a test to check "id" option with
 *       constructed packets
 *       Parse Id Data: expecting ip_id == 41159
 *       The packet has ip_id == 41158 so it must NOT match
 */
int DetectIdTestPacket02 (void) {
    DetectIdData *id_d = NULL;

    id_d = DetectIdParse("41159 ");
    if (id_d == NULL) {
        SCLogDebug("DetectIdTestPacket01: expected a DetectIdData pointer"
                   " (got NULL)\n");
        return 0;
    }
    /* Buid and decode the packet */
    uint8_t raw_eth [] = {
        0x00, 0x14, 0xf8, 0x50, 0xf9, 0x09, 0x00, 0x10,
        0xdc, 0x4f, 0xe6, 0x09, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0xa0, 0xc6, 0x40, 0x00, 0x40, 0x06,
        0xab, 0x46, 0xc0, 0xa8, 0x00, 0xdc, 0x4b, 0x7d,
        0xe1, 0xad, 0xbe, 0x23, 0x00, 0x50, 0xf4, 0x66,
        0x71, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x45, 0xf0, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x06, 0xae,
        0xd1, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06 };

    Packet q;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&q, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&tv, &dtv, &q, raw_eth, sizeof(raw_eth), NULL);
    FlowShutdown();

    Packet *p=&q;

    if (!(PKT_IS_IPV4(p))) {
        SCLogDebug("detect-id: TestPacket01: Packet is not IPV4\n");
        return 0;
    }

    DetectEngineThreadCtx *det_ctx=NULL;
    Signature *s=NULL;

    SigMatch m;
    m.ctx=id_d;

    /* Now that we have what we need, just try "not" to Match! */
    if (DetectIdMatch (&tv, det_ctx, p, s, &m))
        return 0;
    else
        return 1;
}

/**
 * \test SigTest41IdKeyword01Real
 * \brief Test to check "id" keyword with constructed packets,
 * \brief expecting to match the ip->id
 */
int DetectIdTestSig1(void) {
    int result = 1;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
        0x00, 0x14, 0xf8, 0x50, 0xf9, 0x09, 0x00, 0x10,
        0xdc, 0x4f, 0xe6, 0x09, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0xa0, 0xc6, 0x40, 0x00, 0x40, 0x06,
        0xab, 0x46, 0xc0, 0xa8, 0x00, 0xdc, 0x4b, 0x7d,
        0xe1, 0xad, 0xbe, 0x23, 0x00, 0x50, 0xf4, 0x66,
        0x71, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x45, 0xf0, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x06, 0xae,
        0xd1, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06 };

    Packet p;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, &p, raw_eth, sizeof(raw_eth), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any"
                                      " (msg:\"SigTest41IdKeyword01 match\";"
                                      " id:41158; sid:10141;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 10141) == 0) {
        result=0;
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();

    return result;

end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    FlowShutdown();

    return result;
}

/**
 * \test
 * \brief Test to check "id" keyword with constructed packets,
 * \brief not expecting to match the ip->id
 */
int DetectIdTestSig2(void) {
    int result = 1;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
        0x00, 0x14, 0xf8, 0x50, 0xf9, 0x09, 0x00, 0x10,
        0xdc, 0x4f, 0xe6, 0x09, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x3c, 0xa0, 0xc6, 0x40, 0x00, 0x40, 0x06,
        0xab, 0x46, 0xc0, 0xa8, 0x00, 0xdc, 0x4b, 0x7d,
        0xe1, 0xad, 0xbe, 0x23, 0x00, 0x50, 0xf4, 0x66,
        0x71, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
        0x16, 0xd0, 0x45, 0xf0, 0x00, 0x00, 0x02, 0x04,
        0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x06, 0xae,
        0xd1, 0x23, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
        0x03, 0x06 };

    Packet p;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&p, 0, sizeof(Packet));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, &p, raw_eth, sizeof(raw_eth), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result=0;
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any"
                                      " (msg:\"SigTest42IdKeyword02"
                                      " I should not match!\";"
                                      " id:41159; sid:10142;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 10142) == 1) {
        result = 0;
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();

    return result;

end:
    if (de_ctx)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx)
             DetectEngineCtxFree(de_ctx);

    FlowShutdown();

    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectId
 */
void DetectIdRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectIdTestParse01", DetectIdTestParse01, 1);
    UtRegisterTest("DetectIdTestParse02", DetectIdTestParse02, 1);
    UtRegisterTest("DetectIdTestParse03", DetectIdTestParse03, 1);
    UtRegisterTest("DetectIdTestParse04", DetectIdTestParse04, 1);
    UtRegisterTest("DetectIdTestPacket01", DetectIdTestPacket01  , 1);
    UtRegisterTest("DetectIdTestPacket02", DetectIdTestPacket02  , 1);
    UtRegisterTest("DetectIdTestSig1", DetectIdTestSig1, 1);
    UtRegisterTest("DetectIdTestSig2", DetectIdTestSig2, 1);

#endif /* UNITTESTS */
}
