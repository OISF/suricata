/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements support for ja3.hash keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-ja3-hash.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"
#include "util-ja3.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsJa3HashSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTlsJa3HashRegisterTests(void);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static void DetectTlsJa3HashSetupCallback(const DetectEngineCtx *de_ctx,
       Signature *s);
static _Bool DetectTlsJa3HashValidateCallback(const Signature *s,
       const char **sigerror);
static int g_tls_ja3_hash_buffer_id = 0;

/**
 * \brief Registration function for keyword: ja3_hash
 */
void DetectTlsJa3HashRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].name = "ja3.hash";
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].alias = "ja3_hash";
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].desc = "content modifier to match the JA3 hash buffer";
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].url = DOC_URL DOC_VERSION "/rules/ja3-keywords.html#ja3-hash";
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].Setup = DetectTlsJa3HashSetup;
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].Free = NULL;
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].RegisterTests = DetectTlsJa3HashRegisterTests;

    sigmatch_table[DETECT_AL_TLS_JA3_HASH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_JA3_HASH].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("ja3.hash", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("ja3.hash", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("ja3.hash", "TLS JA3 hash");

    DetectBufferTypeRegisterSetupCallback("ja3.hash",
            DetectTlsJa3HashSetupCallback);

    DetectBufferTypeRegisterValidateCallback("ja3.hash",
            DetectTlsJa3HashValidateCallback);

    g_tls_ja3_hash_buffer_id = DetectBufferTypeGetByName("ja3.hash");
}

/**
 * \brief this function setup the ja3.hash modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0 On success
 */
static int DetectTlsJa3HashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectBufferSetActiveList(s, g_tls_ja3_hash_buffer_id);
    s->alproto = ALPROTO_TLS;

    if (RunmodeIsUnittests())
        return 0;

    /* Check if JA3 is disabled */
    if (Ja3IsDisabled("rule"))
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->ja3_hash == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->ja3_hash);
        const uint8_t *data = (uint8_t *)ssl_state->ja3_hash;

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static _Bool DetectTlsJa3HashValidateCallback(const Signature *s,
                                              const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_tls_ja3_hash_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "ja3.hash should not be used together with "
                        "nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len == 32)
            return TRUE;

        *sigerror = "Invalid length of the specified JA3 hash (should "
                    "be 32 characters long). This rule will therefore "
                    "never match.";
        SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
        return FALSE;
    }

    return TRUE;
}

static void DetectTlsJa3HashSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_tls_ja3_hash_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        _Bool changed = FALSE;
        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (isupper(cd->content[u])) {
                cd->content[u] = tolower(cd->content[u]);
                changed = TRUE;
            }
        }

        /* recreate the context if changes were made */
        if (changed) {
            SpmDestroyCtx(cd->spm_ctx);
            cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
                                     de_ctx->spm_global_thread_ctx);
        }
    }
}

#ifndef HAVE_NSS

static void DetectTlsJa3HashRegisterTests(void)
{
    /* Don't register any tests */
}

#else /* HAVE_NSS */

#ifdef UNITTESTS

/**
 * \test Test matching on a simple client hello packet
 */
static int DetectTlsJa3HashTest01(void)
{
    /* Client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x03, 0x00, 0x82, 0x01, 0x00, 0x00, 0x7E,
                      0x03, 0x03, 0x57, 0x04, 0x9F, 0x5D, 0xC9, 0x5C, 0x87,
                      0xAE, 0xF2, 0xA7, 0x4A, 0xFC, 0x59, 0x78, 0x23, 0x31,
                      0x61, 0x2D, 0x29, 0x92, 0xB6, 0x70, 0xA5, 0xA1, 0xFC,
                      0x0E, 0x79, 0xFE, 0xC3, 0x97, 0x37, 0xC0, 0x00, 0x00,
                      0x44, 0x00, 0x04, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x0D,
                      0x00, 0x10, 0x00, 0x13, 0x00, 0x16, 0x00, 0x2F, 0x00,
                      0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00, 0x35,
                      0x00, 0x36, 0x00, 0x37, 0x00, 0x38, 0x00, 0x39, 0x00,
                      0x3C, 0x00, 0x3D, 0x00, 0x3E, 0x00, 0x3F, 0x00, 0x40,
                      0x00, 0x41, 0x00, 0x44, 0x00, 0x45, 0x00, 0x66, 0x00,
                      0x67, 0x00, 0x68, 0x00, 0x69, 0x00, 0x6A, 0x00, 0x6B,
                      0x00, 0x84, 0x00, 0x87, 0x00, 0xFF, 0x01, 0x00, 0x00,
                      0x13, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x0D, 0x00, 0x00,
                      0x0A, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63,
                      0x6F, 0x6D, };


    Flow f;
    SSLState *ssl_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 443);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test ja3.hash\"; ja3.hash; "
                              "content:\"e7eca2baf4458d095b7f45da28c16c34\"; "
                              "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF_NULL(ssl_state->ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test matching on a simple client hello packet
 */
static int DetectTlsJa3HashTest02(void)
{
    /* Client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x01, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xbc,
                      0x03, 0x03, 0x03, 0xb7, 0x16, 0x16, 0x5a, 0xe7, 0xc1,
                      0xbd, 0x46, 0x2f, 0xff, 0xf3, 0x68, 0xb8, 0x6f, 0x6e,
                      0x93, 0xdf, 0x06, 0x6a, 0xa7, 0x2d, 0xa0, 0xea, 0x9f,
                      0x48, 0xb5, 0xe7, 0x91, 0x20, 0xd7, 0x25, 0x00, 0x00,
                      0x1c, 0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                      0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0,
                      0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
                      0x00, 0x0a, 0x01, 0x00, 0x00, 0x77, 0x1a, 0x1a, 0x00,
                      0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                      0x12, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x77, 0x77, 0x77,
                      0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x6e,
                      0x6f, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00,
                      0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08,
                      0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
                      0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00,
                      0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
                      0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68,
                      0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e,
                      0x31, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
                      0x00, 0x0a, 0x00, 0x08, 0xba, 0xba, 0x00, 0x1d, 0x00,
                      0x17, 0x00, 0x18, 0x0a, 0x0a, 0x00, 0x01, 0x00 };

    Flow f;
    SSLState *ssl_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 443);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test ja3.hash\"; ja3.hash; "
                              "content:\"bc6c386f480ee97b9d9e52d472b772d8\"; "
                              "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF_NULL(ssl_state->ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}
#endif /* UNITTESTS */

static void DetectTlsJa3HashRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTlsJa3HashTest01", DetectTlsJa3HashTest01);
    UtRegisterTest("DetectTlsJa3HashTest02", DetectTlsJa3HashTest02);
#endif /* UNITTESTS */
}

#endif /* HAVE_NSS */
