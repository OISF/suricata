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
 * \test Test krb5_msg_type against a KRB-ERROR packet.
 */
static int DetectKrb5MsgTypeKrbError(void)
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

    uint8_t krb_error[] = {
        0x00, 0x00, 0x00, 0xc2, 0x7e, 0x81, 0xbf, 0x30,
        0x81, 0xbc, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1,
        0x03, 0x02, 0x01, 0x1e, 0xa4, 0x11, 0x18, 0x0f,
        0x32, 0x30, 0x32, 0x31, 0x30, 0x36, 0x32, 0x32,
        0x30, 0x39, 0x32, 0x37, 0x34, 0x30, 0x5a, 0xa5,
        0x05, 0x02, 0x03, 0x09, 0xe9, 0x10, 0xa6, 0x03,
        0x02, 0x01, 0x19, 0xa9, 0x0c, 0x1b, 0x0a, 0x43,
        0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c, 0x41,
        0x42, 0xaa, 0x1f, 0x30, 0x1d, 0xa0, 0x03, 0x02,
        0x01, 0x02, 0xa1, 0x16, 0x30, 0x14, 0x1b, 0x06,
        0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0a,
        0x43, 0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c,
        0x41, 0x42, 0xac, 0x62, 0x04, 0x60, 0x30, 0x5e,
        0x30, 0x3b, 0xa1, 0x03, 0x02, 0x01, 0x13, 0xa2,
        0x34, 0x04, 0x32, 0x30, 0x30, 0x30, 0x18, 0xa0,
        0x03, 0x02, 0x01, 0x12, 0xa1, 0x11, 0x1b, 0x0f,
        0x43, 0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c,
        0x41, 0x42, 0x72, 0x6f, 0x62, 0x69, 0x6e, 0x30,
        0x05, 0xa0, 0x03, 0x02, 0x01, 0x17, 0x30, 0x06,
        0xa0, 0x04, 0x02, 0x02, 0xff, 0x7b, 0x30, 0x05,
        0xa0, 0x03, 0x02, 0x01, 0x80, 0x30, 0x09, 0xa1,
        0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00,
        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x10, 0xa2,
        0x02, 0x04, 0x00, 0x30, 0x09, 0xa1, 0x03, 0x02,
        0x01, 0x0f, 0xa2, 0x02, 0x04, 0x00
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
                                   "krb5_msg_type: 30; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_KRB5,
                            STREAM_TOSERVER | STREAM_START, krb_error,
                            sizeof(krb_error));

    if (r != 0) {
        SCLogDebug("AppLayerParse for krb5 failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)){
        SCLogDebug("Kerberos KRB-ERROR signature didn't match");
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
 * \test Test krb5_msg_type against a TGS-REQ packet.
 */
static int DetectKrb5MsgTypeTgsReq(void)
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

    uint8_t tgs_req[] = {
        0x00, 0x00, 0x06, 0x0f, 0x6c, 0x82, 0x06, 0x0b,
        0x30, 0x82, 0x06, 0x07, 0xa1, 0x03, 0x02, 0x01,
        0x05, 0xa2, 0x03, 0x02, 0x01, 0x0c, 0xa3, 0x82,
        0x04, 0xfb, 0x30, 0x82, 0x04, 0xf7, 0x30, 0x82,
        0x04, 0xdc, 0xa1, 0x03, 0x02, 0x01, 0x01, 0xa2,
        0x82, 0x04, 0xd3, 0x04, 0x82, 0x04, 0xcf, 0x6e,
        0x82, 0x04, 0xcb, 0x30, 0x82, 0x04, 0xc7, 0xa0,
        0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01,
        0x0e, 0xa2, 0x07, 0x03, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xa3, 0x82, 0x04, 0x1a, 0x61, 0x82,
        0x04, 0x16, 0x30, 0x82, 0x04, 0x12, 0xa0, 0x03,
        0x02, 0x01, 0x05, 0xa1, 0x0c, 0x1b, 0x0a, 0x43,
        0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c, 0x41,
        0x42, 0xa2, 0x1f, 0x30, 0x1d, 0xa0, 0x03, 0x02,
        0x01, 0x02, 0xa1, 0x16, 0x30, 0x14, 0x1b, 0x06,
        0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, 0x1b, 0x0a,
        0x43, 0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c,
        0x41, 0x42, 0xa3, 0x82, 0x03, 0xda, 0x30, 0x82,
        0x03, 0xd6, 0xa0, 0x03, 0x02, 0x01, 0x12, 0xa1,
        0x03, 0x02, 0x01, 0x02, 0xa2, 0x82, 0x03, 0xc8,
        0x04, 0x82, 0x03, 0xc4, 0xa8, 0xb2, 0x40, 0x98,
        0xa1, 0xe4, 0x98, 0xfc, 0xc1, 0x2a, 0x01, 0x88,
        0x6f, 0xb1, 0xc6, 0x44, 0xa1, 0xb2, 0x38, 0x47,
        0xd8, 0x22, 0x6e, 0xe2, 0x0e, 0x95, 0xe3, 0x59,
        0x7e, 0x3d, 0x63, 0xac, 0xf4, 0xd9, 0x73, 0x6e,
        0xbe, 0x20, 0xf9, 0xfb, 0x0c, 0x06, 0x41, 0x86,
        0xb0, 0x30, 0x0b, 0xea, 0x10, 0xa3, 0x8a, 0x6f,
        0x4c, 0x05, 0xd6, 0xeb, 0xd5, 0xf5, 0x69, 0xe9,
        0x86, 0xd0, 0x2c, 0x47, 0x2b, 0x6b, 0xea, 0x55,
        0x0e, 0x01, 0xab, 0x9b, 0x5f, 0xc3, 0xb7, 0xa1,
        0x7a, 0xf4, 0x45, 0x4b, 0xce, 0x0c, 0xa0, 0xd9,
        0x26, 0xb0, 0x9a, 0xee, 0xff, 0x69, 0x67, 0x85,
        0x11, 0x27, 0xd9, 0x63, 0x32, 0x07, 0xa7, 0x57,
        0x35, 0xda, 0x33, 0x24, 0xe9, 0xb8, 0x2f, 0x9e,
        0xaf, 0x73, 0xd0, 0x4a, 0x96, 0x56, 0xe9, 0xdf,
        0x18, 0xdb, 0x39, 0x35, 0x02, 0x36, 0x2e, 0x86,
        0x0a, 0x60, 0x7c, 0x6a, 0x6c, 0x4a, 0x66, 0x82,
        0x87, 0x0b, 0x2e, 0x62, 0x70, 0x30, 0x0d, 0x56,
        0x37, 0x02, 0xbc, 0xa7, 0x21, 0xf1, 0x18, 0xe4,
        0x10, 0xde, 0x56, 0x2b, 0x2e, 0x8b, 0x65, 0xc8,
        0x0b, 0x43, 0xee, 0x91, 0x99, 0x62, 0x61, 0xa5,
        0xfe, 0xd3, 0xd9, 0xd3, 0x08, 0x2e, 0x88, 0x22,
        0x88, 0xf7, 0x9d, 0x7a, 0x92, 0x65, 0x3c, 0x5a,
        0x75, 0x96, 0x13, 0x88, 0x3f, 0xa1, 0x5b, 0xd5,
        0x70, 0x47, 0x1d, 0xaa, 0x84, 0xa8, 0xb7, 0x2c,
        0xe8, 0xf3, 0xaf, 0x6e, 0xf6, 0xa4, 0x73, 0xdc,
        0x1f, 0x2d, 0x7c, 0xe8, 0x6c, 0xe0, 0xaf, 0xdb,
        0x4b, 0x10, 0x94, 0x8d, 0x7f, 0xbc, 0x2f, 0x4f,
        0x09, 0xdd, 0x9d, 0x2f, 0x8d, 0xc8, 0x4d, 0xc8,
        0x60, 0xe0, 0x4a, 0xa8, 0x4f, 0x0a, 0xb8, 0xca,
        0x52, 0xa2, 0xd3, 0x7b, 0xf6, 0x98, 0x09, 0x06,
        0xe0, 0x45, 0x03, 0xf1, 0x41, 0x13, 0x8c, 0x14,
        0xc5, 0x2d, 0x47, 0xce, 0xa3, 0xce, 0x31, 0xc1,
        0xb2, 0x4d, 0x8b, 0x5f, 0x10, 0x30, 0x71, 0xd1,
        0x58, 0x92, 0xb4, 0x96, 0x70, 0xb5, 0xb7, 0xb5,
        0xdd, 0x98, 0xbf, 0xa1, 0x51, 0x73, 0xc9, 0x99,
        0xfb, 0x7c, 0x53, 0xd7, 0x78, 0x04, 0x1f, 0x52,
        0x1e, 0x9d, 0xcd, 0x8c, 0x8d, 0x79, 0x6d, 0xcf,
        0xe7, 0xc3, 0x7e, 0x8d, 0x9e, 0xda, 0x1c, 0x6c,
        0x6f, 0x5c, 0xea, 0x9e, 0x0e, 0xb9, 0xc1, 0x6e,
        0xaf, 0x18, 0xe1, 0x47, 0xb2, 0xda, 0x20, 0x00,
        0x3c, 0x28, 0xbc, 0xb2, 0xdf, 0x97, 0xd7, 0xa1,
        0x9b, 0x5a, 0x9b, 0xde, 0x8a, 0xff, 0xef, 0x2a,
        0x14, 0xf3, 0xcf, 0xaf, 0x14, 0xa7, 0x86, 0x6e,
        0x39, 0x9e, 0x8e, 0x5b, 0x7f, 0x2b, 0xb6, 0x8f,
        0x65, 0x0c, 0x51, 0xf0, 0x45, 0x20, 0x92, 0xf6,
        0x02, 0x40, 0x95, 0xa6, 0x63, 0x65, 0x91, 0xc2,
        0xd6, 0xc5, 0x5f, 0xbc, 0x59, 0x76, 0xac, 0xb6,
        0xbd, 0xbb, 0xb3, 0xb7, 0x7b, 0x29, 0xfa, 0xfc,
        0x23, 0x62, 0xf7, 0x18, 0x40, 0x26, 0xe7, 0x17,
        0xea, 0xb2, 0xa6, 0x92, 0x69, 0xee, 0xe9, 0xec,
        0xeb, 0x5f, 0x3d, 0x66, 0x90, 0x4f, 0x87, 0x1d,
        0xd2, 0x1a, 0x22, 0xeb, 0x48, 0x0a, 0x60, 0xfe,
        0x41, 0xf1, 0x98, 0x09, 0x90, 0x62, 0x62, 0xab,
        0x99, 0xac, 0x6e, 0xc3, 0xe1, 0x2a, 0x51, 0x93,
        0x7d, 0x98, 0x2c, 0x3a, 0xc1, 0x98, 0x37, 0xe2,
        0x7e, 0x3e, 0x1b, 0x10, 0x55, 0x29, 0xac, 0xd4,
        0xd3, 0xa6, 0x23, 0xe6, 0x90, 0xf7, 0x7f, 0x63,
        0x5e, 0xf2, 0xf5, 0xc4, 0x64, 0xe7, 0x65, 0xc6,
        0x0e, 0x6b, 0x80, 0xe3, 0xec, 0xa9, 0x1e, 0x2d,
        0x77, 0x8e, 0x17, 0x6d, 0x09, 0x2d, 0x7d, 0x41,
        0x2e, 0x68, 0x62, 0x04, 0x89, 0xa8, 0xed, 0x7c,
        0x45, 0x88, 0x1e, 0x26, 0x13, 0x0f, 0x41, 0x6b,
        0x22, 0xc4, 0xae, 0x2e, 0xa8, 0xbf, 0x86, 0x11,
        0xa7, 0x5e, 0xf7, 0xd8, 0x3b, 0xc4, 0x49, 0x60,
        0x9a, 0x6e, 0x13, 0xa2, 0x89, 0xfe, 0xe4, 0xed,
        0x9d, 0x82, 0x1a, 0x6d, 0x9a, 0x33, 0x89, 0x1d,
        0x1d, 0xdc, 0x00, 0x15, 0x13, 0x87, 0x99, 0x56,
        0x56, 0x0c, 0xbc, 0x66, 0x9f, 0x59, 0x47, 0xaa,
        0x92, 0x87, 0x6c, 0x12, 0xe3, 0x78, 0x26, 0x5c,
        0xcf, 0x49, 0x95, 0xa1, 0x38, 0x0a, 0xbd, 0xe3,
        0x99, 0x31, 0xe7, 0x63, 0x87, 0x69, 0x93, 0xac,
        0xe9, 0x7a, 0xca, 0xb5, 0xcd, 0xfe, 0x0a, 0x1e,
        0xb3, 0x6e, 0x85, 0x20, 0xf9, 0x19, 0xb5, 0x36,
        0x35, 0xd9, 0xbb, 0x59, 0xf2, 0x40, 0xf3, 0x9f,
        0x89, 0x87, 0x69, 0x54, 0x6f, 0xfd, 0x4f, 0xcf,
        0x05, 0xc0, 0x4a, 0x49, 0x0c, 0xea, 0xf3, 0x7e,
        0x9c, 0x56, 0x34, 0xe3, 0xc6, 0xfc, 0x13, 0xbe,
        0xe6, 0x9a, 0x2c, 0x7d, 0x9a, 0xcc, 0x02, 0x65,
        0xbb, 0xcd, 0x6c, 0x42, 0xaf, 0x12, 0xe3, 0x06,
        0xae, 0x2e, 0x0f, 0x0e, 0x04, 0xcb, 0xc4, 0x79,
        0x12, 0xc1, 0x69, 0x09, 0x71, 0x74, 0x22, 0x2d,
        0xfa, 0x54, 0xc1, 0x9f, 0x70, 0x57, 0x98, 0xb3,
        0xa2, 0xa7, 0xe0, 0x99, 0xd2, 0x9c, 0xea, 0xd7,
        0x76, 0x2a, 0xc5, 0xea, 0x0d, 0x06, 0x69, 0x1c,
        0x96, 0xff, 0xeb, 0x9d, 0x5a, 0xa0, 0x33, 0x6a,
        0x2a, 0x51, 0xdf, 0x21, 0x60, 0x67, 0xe5, 0x3e,
        0x86, 0x65, 0x07, 0x7d, 0x39, 0xaa, 0xa7, 0xb6,
        0x6c, 0x1e, 0x4e, 0x46, 0xc0, 0x4f, 0xb0, 0x00,
        0x70, 0xa5, 0x28, 0xb2, 0xa5, 0xf2, 0x34, 0xdf,
        0x0e, 0xc5, 0xd6, 0xb3, 0x88, 0x60, 0xd1, 0x0c,
        0x75, 0xb7, 0x4d, 0x34, 0x10, 0x24, 0xa0, 0x35,
        0x84, 0x8d, 0x25, 0xd9, 0x7d, 0xe5, 0x99, 0x47,
        0xcd, 0x06, 0x51, 0xb2, 0x6a, 0x3d, 0x64, 0x71,
        0xee, 0x93, 0xb7, 0x96, 0xf3, 0xdf, 0x1b, 0xef,
        0x0f, 0x5e, 0x99, 0xdf, 0x77, 0x7c, 0xab, 0x11,
        0x80, 0x52, 0xea, 0x3e, 0x08, 0xf5, 0xab, 0x43,
        0xcb, 0x76, 0x7a, 0x56, 0x88, 0x80, 0xc7, 0xb2,
        0x45, 0x49, 0x7f, 0xfc, 0x2d, 0x18, 0xc9, 0x93,
        0x0f, 0x9c, 0x1a, 0x42, 0x2a, 0xd8, 0x16, 0xed,
        0x6f, 0xc8, 0x9d, 0x09, 0x45, 0x6e, 0x59, 0x46,
        0x4c, 0xb7, 0x00, 0xa6, 0xad, 0xbd, 0xbc, 0x0e,
        0xff, 0xf1, 0xe7, 0x15, 0x0d, 0xb2, 0xf8, 0x46,
        0xee, 0xe2, 0xc0, 0x27, 0x1d, 0x89, 0x84, 0x06,
        0x85, 0x30, 0x87, 0x69, 0x73, 0xd6, 0x05, 0x9e,
        0xd3, 0xc4, 0x93, 0x9d, 0xd8, 0x61, 0xc4, 0x81,
        0xcd, 0x87, 0x52, 0x08, 0x62, 0x76, 0x6d, 0x44,
        0xb1, 0x8a, 0x92, 0x06, 0xf8, 0xd2, 0xb2, 0x5d,
        0x07, 0x85, 0x2e, 0x7a, 0xc0, 0xd3, 0x58, 0xe0,
        0xdb, 0xf2, 0x45, 0xf9, 0x38, 0xb9, 0x72, 0x93,
        0xc2, 0xa5, 0x6c, 0xd4, 0x97, 0x70, 0xc8, 0x64,
        0x56, 0x26, 0x47, 0x37, 0x9e, 0x85, 0xac, 0xed,
        0x48, 0x29, 0x3e, 0xa1, 0xa3, 0x7b, 0x5f, 0x27,
        0xd2, 0xa3, 0xb3, 0x9a, 0x1c, 0xc8, 0xf3, 0x3d,
        0xb2, 0xaf, 0xc9, 0x8c, 0xb6, 0x6f, 0x2d, 0xc0,
        0x0b, 0xc9, 0xf6, 0xfd, 0xf6, 0xb1, 0xe9, 0x8b,
        0xff, 0x0c, 0xb1, 0x55, 0x30, 0xbb, 0x91, 0xef,
        0xde, 0x1f, 0xdf, 0xfb, 0xdf, 0x49, 0xa0, 0xbd,
        0x04, 0x2f, 0x75, 0xdf, 0x61, 0x4b, 0xf9, 0x27,
        0xfd, 0xb0, 0x5a, 0x98, 0xd1, 0x23, 0xef, 0xd4,
        0x4b, 0xe4, 0xfd, 0x08, 0xd0, 0xf1, 0x66, 0xba,
        0xa4, 0x81, 0x93, 0x30, 0x81, 0x90, 0xa0, 0x03,
        0x02, 0x01, 0x12, 0xa2, 0x81, 0x88, 0x04, 0x81,
        0x85, 0xee, 0xa4, 0x4d, 0x43, 0xcc, 0x2f, 0xe0,
        0xc9, 0x12, 0xf5, 0xf1, 0xbd, 0x9c, 0x2b, 0xda,
        0xf3, 0xca, 0x1d, 0x2a, 0xda, 0x70, 0xae, 0xfb,
        0xf2, 0x07, 0xfa, 0x81, 0xea, 0x9d, 0xc7, 0x0d,
        0xe7, 0xc7, 0xcc, 0xa1, 0xa9, 0x5d, 0x28, 0x5c,
        0x4a, 0x68, 0xf0, 0xfe, 0x80, 0x87, 0x94, 0x25,
        0x71, 0x9f, 0xce, 0xb3, 0x69, 0x24, 0x41, 0xf5,
        0xe5, 0x83, 0xe2, 0x12, 0xf0, 0xdf, 0x2c, 0x22,
        0x80, 0x59, 0x07, 0x80, 0x5b, 0x18, 0x2a, 0x0f,
        0x71, 0xbf, 0xc0, 0x85, 0x1b, 0x80, 0x94, 0x68,
        0xc5, 0x90, 0xe1, 0x1f, 0x4c, 0xee, 0xa6, 0x36,
        0x01, 0xba, 0x7c, 0x93, 0x35, 0x71, 0x92, 0xe9,
        0xfa, 0x42, 0x12, 0x6f, 0x77, 0xc8, 0xaa, 0x4d,
        0x97, 0x07, 0xa1, 0xc8, 0xb9, 0xaf, 0xd6, 0x0b,
        0x1d, 0x68, 0x84, 0x60, 0x95, 0xb8, 0x7e, 0xd6,
        0x53, 0xb1, 0x9f, 0x6a, 0x88, 0xdb, 0x0a, 0xff,
        0xda, 0xf5, 0x2c, 0xd6, 0xc5, 0xef, 0x30, 0x15,
        0xa1, 0x04, 0x02, 0x02, 0x00, 0xa7, 0xa2, 0x0d,
        0x04, 0x0b, 0x30, 0x09, 0xa0, 0x07, 0x03, 0x05,
        0x00, 0x40, 0x00, 0x00, 0x00, 0xa4, 0x81, 0xfb,
        0x30, 0x81, 0xf8, 0xa0, 0x07, 0x03, 0x05, 0x00,
        0x40, 0x81, 0x00, 0x00, 0xa2, 0x0c, 0x1b, 0x0a,
        0x43, 0x59, 0x4c, 0x45, 0x52, 0x41, 0x2e, 0x4c,
        0x41, 0x42, 0xa3, 0x17, 0x30, 0x15, 0xa0, 0x03,
        0x02, 0x01, 0x02, 0xa1, 0x0e, 0x30, 0x0c, 0x1b,
        0x04, 0x6c, 0x64, 0x61, 0x70, 0x1b, 0x04, 0x64,
        0x63, 0x30, 0x31, 0xa5, 0x11, 0x18, 0x0f, 0x32,
        0x30, 0x33, 0x37, 0x30, 0x39, 0x31, 0x33, 0x30,
        0x32, 0x34, 0x38, 0x30, 0x35, 0x5a, 0xa7, 0x06,
        0x02, 0x04, 0x59, 0x0a, 0x0b, 0x8d, 0xa8, 0x12,
        0x30, 0x10, 0x02, 0x01, 0x12, 0x02, 0x01, 0x11,
        0x02, 0x01, 0x17, 0x02, 0x01, 0x18, 0x02, 0x02,
        0xff, 0x79, 0xaa, 0x81, 0x96, 0x30, 0x81, 0x93,
        0xa0, 0x03, 0x02, 0x01, 0x12, 0xa2, 0x81, 0x8b,
        0x04, 0x81, 0x88, 0xab, 0x37, 0xf0, 0xec, 0x1b,
        0xd0, 0xd6, 0x00, 0xc8, 0xe3, 0x21, 0x23, 0xdf,
        0x83, 0xf9, 0xe7, 0x2e, 0x7e, 0x51, 0x7c, 0xa1,
        0x16, 0xe5, 0x26, 0x5e, 0xa5, 0x36, 0x6b, 0x9b,
        0xf1, 0xdb, 0xb0, 0x04, 0x00, 0x03, 0x39, 0x2e,
        0x20, 0x8d, 0x3c, 0x8c, 0x4c, 0xa1, 0x3e, 0x4a,
        0xb5, 0xa7, 0x68, 0x49, 0xf0, 0xf7, 0xad, 0x09,
        0x31, 0x49, 0x5c, 0x6b, 0xd1, 0x47, 0x6c, 0x92,
        0x80, 0x9d, 0xaf, 0x08, 0x31, 0x19, 0x06, 0xbe,
        0x18, 0xb7, 0xee, 0x98, 0xcc, 0x30, 0x86, 0x8e,
        0xe6, 0x4e, 0xef, 0x27, 0x41, 0x65, 0xd1, 0xdb,
        0x79, 0x39, 0x12, 0x18, 0x35, 0x09, 0x16, 0x7c,
        0x43, 0x8d, 0x6f, 0x2c, 0x2c, 0x69, 0x6f, 0x88,
        0x97, 0x52, 0x82, 0xb6, 0xf7, 0x59, 0xfc, 0x1d,
        0x60, 0x0f, 0x42, 0x42, 0x26, 0x2b, 0xbc, 0xed,
        0x0d, 0x4e, 0x4f, 0x95, 0x25, 0x05, 0xf3, 0x04,
        0x4e, 0x0e, 0xfb, 0x49, 0x76, 0x33, 0x3c, 0x68,
        0x9d, 0xde, 0x57
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
                                   "(msg:\"Kerberos TGS-REQ\"; "
                                   "krb5_msg_type: 12; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_KRB5,
                            STREAM_TOSERVER | STREAM_START, tgs_req,
                            sizeof(tgs_req));

    if (r != 0) {
        SCLogDebug("AppLayerParse for krb5 failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)){
        SCLogDebug("Kerberos TGS-REQ signature didn't match");
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
    UtRegisterTest("DetectKrb5MsgTypeTgsReq", DetectKrb5MsgTypeTgsReq);
    UtRegisterTest("DetectKrb5MsgTypeKrbError", DetectKrb5MsgTypeKrbError);
}
#endif /* UNITTESTS */
