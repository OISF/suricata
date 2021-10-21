/* Copyright (C) 2018-2020 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "util-byte.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-krb5-msgtype.h"

#include "app-layer-krb5.h"
#include "rust.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([A-z0-9\\.]+|\"[A-z0-9_\\.]+\")\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectKrb5MsgTypeRegister below */
static int DetectKrb5MsgTypeMatch (DetectEngineThreadCtx *, Flow *,
                                   uint8_t, void *, void *, const Signature *,
                                   const SigMatchCtx *);
static int DetectKrb5MsgTypeSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectKrb5MsgTypeFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectKrb5MsgTypeRegisterTests (void);
#endif

static int DetectEngineInspectKRB5Generic(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

static int g_krb5_msg_type_list_id = 0;

/**
 * \brief Registration function for krb5_msg_type: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectKrb5MsgTypeRegister(void)
{
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].name = "krb5_msg_type";
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].desc = "match Kerberos 5 message type";
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].url = "/rules/kerberos-keywords.html#krb5-msg-type";
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].Match = NULL;
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].AppLayerTxMatch = DetectKrb5MsgTypeMatch;
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].Setup = DetectKrb5MsgTypeSetup;
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].Free = DetectKrb5MsgTypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_KRB5_MSGTYPE].RegisterTests = DetectKrb5MsgTypeRegisterTests;
#endif
    DetectAppLayerInspectEngineRegister("krb5_msg_type",
            ALPROTO_KRB5, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectKRB5Generic);

    DetectAppLayerInspectEngineRegister("krb5_msg_type",
            ALPROTO_KRB5, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectKRB5Generic);

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_krb5_msg_type_list_id = DetectBufferTypeRegister("krb5_msg_type");
    SCLogDebug("g_krb5_msg_type_list_id %d", g_krb5_msg_type_list_id);
}

static int DetectEngineInspectKRB5Generic(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}

/**
 * \brief This function is used to match KRB5 rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectKrb5Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectKrb5MsgTypeMatch (DetectEngineThreadCtx *det_ctx,
                                   Flow *f, uint8_t flags, void *state,
                                   void *txv, const Signature *s,
                                   const SigMatchCtx *ctx)
{
    uint32_t msg_type;
    const DetectKrb5MsgTypeData *dd = (const DetectKrb5MsgTypeData *)ctx;

    SCEnter();

    rs_krb5_tx_get_msgtype(txv, &msg_type);

    if (dd->msg_type == msg_type)
        SCReturnInt(1);

    SCReturnInt(0);
}

/**
 * \brief This function is used to parse options passed via krb5_msgtype: keyword
 *
 * \param krb5str Pointer to the user provided krb5_msg_type options
 *
 * \retval krb5d pointer to DetectKrb5Data on success
 * \retval NULL on failure
 */
static DetectKrb5MsgTypeData *DetectKrb5MsgTypeParse (const char *krb5str)
{
    DetectKrb5MsgTypeData *krb5d = NULL;
    char arg1[4] = "";
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, krb5str, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) krb5str, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    krb5d = SCMalloc(sizeof (DetectKrb5MsgTypeData));
    if (unlikely(krb5d == NULL))
        goto error;
    if (StringParseUint8(&krb5d->msg_type, 10, 0,
                         (const char *)arg1) < 0) {
        goto error;
    }
    return krb5d;

error:
    if (krb5d)
        SCFree(krb5d);
    return NULL;
}

/**
 * \brief parse the options from the 'krb5_msg_type' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param krb5str pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectKrb5MsgTypeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *krb5str)
{
    DetectKrb5MsgTypeData *krb5d = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    krb5d = DetectKrb5MsgTypeParse(krb5str);
    if (krb5d == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_KRB5_MSGTYPE;
    sm->ctx = (void *)krb5d;

    SigMatchAppendSMToList(s, sm, g_krb5_msg_type_list_id);

    return 0;

error:
    if (krb5d != NULL)
        DetectKrb5MsgTypeFree(de_ctx, krb5d);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectKrb5Data
 *
 * \param ptr pointer to DetectKrb5Data
 */
static void DetectKrb5MsgTypeFree(DetectEngineCtx *de_ctx, void *ptr) {
    DetectKrb5MsgTypeData *krb5d = (DetectKrb5MsgTypeData *)ptr;

    SCFree(krb5d);
}

#ifdef UNITTESTS

#include "util-unittest-helper.h"
#include "stream-tcp.h"
#include "app-layer-parser.h"
#include "flow-util.h"

/**
 * \test description of the test
 */

static int DetectKrb5MsgTypeParseTest01 (void)
{
    DetectKrb5MsgTypeData *krb5d = DetectKrb5MsgTypeParse("10");
    FAIL_IF_NULL(krb5d);
    FAIL_IF(!(krb5d->msg_type == 10));
    DetectKrb5MsgTypeFree(NULL, krb5d);
    PASS;
}

static int DetectKrb5MsgTypeSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert krb5 any any -> any any (krb5_msg_type:10; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}


/**
 * \test Test krb5_msg_type against a AS-REQ packet.
 */
static int DetectKrb5MsgTypeAsReq(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int r = 0;

    uint8_t as_req[] = {
        0x00, 0x00, 0x00, 0xde, 0x6a, 0x81, 0xdb, 0x30,
        0x81, 0xd8, 0xa1, 0x03, 0x02, 0x01, 0x05, 0xa2,
        0x03, 0x02, 0x01, 0x0a, 0xa3, 0x15, 0x30, 0x13,
        0x30, 0x11, 0xa1, 0x04, 0x02, 0x02, 0x00, 0x80,
        0xa2, 0x09, 0x04, 0x07, 0x30, 0x05, 0xa0, 0x03,
        0x01, 0x01, 0xff, 0xa4, 0x81, 0xb4, 0x30, 0x81,
        0xb1, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x40, 0x81,
        0x00, 0x10, 0xa1, 0x12, 0x30, 0x10, 0xa0, 0x03,
        0x02, 0x01, 0x01, 0xa1, 0x09, 0x30, 0x07, 0x1b,
        0x05, 0x72, 0x6f, 0x62, 0x69, 0x6e, 0xa2, 0x0c,
        0x1b, 0x0a, 0x43, 0x59, 0x4c, 0x45, 0x52, 0x41,
        0x2e, 0x4c, 0x41, 0x42, 0xa3, 0x1f, 0x30, 0x1d,
        0xa0, 0x03, 0x02, 0x01, 0x02, 0xa1, 0x16, 0x30,
        0x14, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67,
        0x74, 0x1b, 0x0a, 0x43, 0x59, 0x4c, 0x45, 0x52,
        0x41, 0x2e, 0x4c, 0x41, 0x42, 0xa5, 0x11, 0x18,
        0x0f, 0x32, 0x30, 0x33, 0x37, 0x30, 0x39, 0x31,
        0x33, 0x30, 0x32, 0x34, 0x38, 0x30, 0x35, 0x5a,
        0xa6, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x33, 0x37,
        0x30, 0x39, 0x31, 0x33, 0x30, 0x32, 0x34, 0x38,
        0x30, 0x35, 0x5a, 0xa7, 0x06, 0x02, 0x04, 0x59,
        0x0a, 0x0b, 0xb7, 0xa8, 0x16, 0x30, 0x14, 0x02,
        0x01, 0x12, 0x02, 0x01, 0x17, 0x02, 0x02, 0xff,
        0x7b, 0x02, 0x01, 0x80, 0x02, 0x01, 0x18, 0x02,
        0x02, 0xff, 0x79, 0xa9, 0x1d, 0x30, 0x1b, 0x30,
        0x19, 0xa0, 0x03, 0x02, 0x01, 0x14, 0xa1, 0x12,
        0x04, 0x10, 0x57, 0x53, 0x30, 0x31, 0x20, 0x20,
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
        0x20, 0x20
    };

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_KRB5;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert krb5 any any -> any any "
                                   "(msg:\"Kerberos AS-REQ\"; "
                                   "krb5_msg_type: 10; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_KRB5,
                            STREAM_TOSERVER | STREAM_START, as_req,
                            sizeof(as_req));

    if (r != 0) {
        SCLogDebug("AppLayerParse for krb5 failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)){
        SCLogDebug("Kerberos AS-REQ signature didn't match");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}


/**
 * \brief this function registers unit tests for DetectKrb5MsgType
 */
static void DetectKrb5MsgTypeRegisterTests(void)
{
    UtRegisterTest("DetectKrb5MsgTypeParseTest01", DetectKrb5MsgTypeParseTest01);
    UtRegisterTest("DetectKrb5MsgTypeSignatureTest01",
                   DetectKrb5MsgTypeSignatureTest01);

    UtRegisterTest("DetectKrb5MsgTypeAsReq", DetectKrb5MsgTypeAsReq);
}
#endif /* UNITTESTS */
