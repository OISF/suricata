/* Copyright (C) 2019 Open Information Security Foundation
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
 * Implements support for ja3s.hash keyword.
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
#include "detect-tls-ja3s-hash.h"

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

static int DetectTlsJa3SHashSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTlsJa3SHashRegisterTests(void);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static void DetectTlsJa3SHashSetupCallback(const DetectEngineCtx *de_ctx,
       Signature *s);
static _Bool DetectTlsJa3SHashValidateCallback(const Signature *s,
       const char **sigerror);
static int g_tls_ja3s_hash_buffer_id = 0;

/**
 * \brief Registration function for keyword: ja3s.hash
 */
void DetectTlsJa3SHashRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].name = "ja3s.hash";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].desc = "content modifier to match the JA3S hash sticky buffer";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].url = DOC_URL DOC_VERSION "/rules/ja3-keywords.html#ja3s-hash";
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].Setup = DetectTlsJa3SHashSetup;
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].RegisterTests = DetectTlsJa3SHashRegisterTests;

    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_JA3S_HASH].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("ja3s.hash", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("ja3s.hash", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("ja3s.hash", "TLS JA3S hash");

    DetectBufferTypeRegisterSetupCallback("ja3s.hash",
            DetectTlsJa3SHashSetupCallback);

    DetectBufferTypeRegisterValidateCallback("ja3s.hash",
            DetectTlsJa3SHashValidateCallback);

    g_tls_ja3s_hash_buffer_id = DetectBufferTypeGetByName("ja3s.hash");
}

/**
 * \brief this function setup the ja3s.hash modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsJa3SHashSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_ja3s_hash_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    /* Check if JA3 is disabled */
    if (!RunmodeIsUnittests() && Ja3IsDisabled("rule"))
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->server_connp.ja3_hash == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->server_connp.ja3_hash);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.ja3_hash;

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static _Bool DetectTlsJa3SHashValidateCallback(const Signature *s,
                                               const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_tls_ja3s_hash_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "ja3s.hash should not be used together with "
                        "nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len == 32)
            return TRUE;

        *sigerror = "Invalid length of the specified JA3S hash (should "
                    "be 32 characters long). This rule will therefore "
                    "never match.";
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,  "rule %u: %s", s->id, *sigerror);
        return FALSE;
    }

    return TRUE;
}

static void DetectTlsJa3SHashSetupCallback(const DetectEngineCtx *de_ctx,
                                           Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_tls_ja3s_hash_buffer_id];
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

static void DetectTlsJa3SHashRegisterTests(void)
{
    /* Don't register any tests */
}

#else /* HAVE_NSS */

#ifdef UNITTESTS

/**
 * \test Test matching on a JA3S hash from a ServerHello record
 */
static int DetectTlsJa3SHashTest01(void)
{
    /* client hello */
    uint8_t client_hello[] = {
            0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00,
            0xc4, 0x03, 0x03, 0xd6, 0x08, 0x5a, 0xa2, 0x86,
            0x5b, 0x85, 0xd4, 0x40, 0xab, 0xbe, 0xc0, 0xbc,
            0x41, 0xf2, 0x26, 0xf0, 0xfe, 0x21, 0xee, 0x8b,
            0x4c, 0x7e, 0x07, 0xc8, 0xec, 0xd2, 0x00, 0x46,
            0x4c, 0xeb, 0xb7, 0x00, 0x00, 0x16, 0xc0, 0x2b,
            0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13,
            0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f,
            0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x85,
            0x00, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0x00,
            0x0d, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x2e, 0x6e, 0x6f, 0xff, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00,
            0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00,
            0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
            0x00, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x29, 0x00, 0x27, 0x05, 0x68, 0x32, 0x2d, 0x31,
            0x36, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x35, 0x05,
            0x68, 0x32, 0x2d, 0x31, 0x34, 0x02, 0x68, 0x32,
            0x08, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e,
            0x31, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
            0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16, 0x00,
            0x14, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02,
            0x01, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
            0x03, 0x04, 0x02, 0x02, 0x02
    };

    /* server hello */
    uint8_t server_hello[] = {
            0x16, 0x03, 0x03, 0x00, 0x48, 0x02, 0x00, 0x00,
            0x44, 0x03, 0x03, 0x57, 0x91, 0xb8, 0x63, 0xdd,
            0xdb, 0xbb, 0x23, 0xcf, 0x0b, 0x43, 0x02, 0x1d,
            0x46, 0x11, 0x27, 0x5c, 0x98, 0xcf, 0x67, 0xe1,
            0x94, 0x3d, 0x62, 0x7d, 0x38, 0x48, 0x21, 0x23,
            0xa5, 0x62, 0x31, 0x00, 0xc0, 0x2f, 0x00, 0x00,
            0x1c, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10,
            0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32, 0x00,
            0x0b, 0x00, 0x02, 0x01, 0x00
    };

    Flow f;
    SSLState *ssl_state = NULL;
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacketReal(client_hello, sizeof(client_hello), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1", 51251, 443);
    p2 = UTHBuildPacketReal(server_hello, sizeof(server_hello), IPPROTO_TCP,
                            "192.168.1.1", "192.168.1.5", 443, 51251);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_TLS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->pcap_cnt = 2;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                                "(msg:\"Test ja3s.hash\"; "
                                "ja3s.hash; "
                                "content:\"8217013c502e3461d19c75bb02a12aaf\"; "
                                "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                sizeof(client_hello));

    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello, sizeof(server_hello));

    FAIL_IF(r != 0);

    FAIL_IF_NULL(ssl_state->server_connp.ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);

    PASS;
}

#endif /* UNITTESTS */

static void DetectTlsJa3SHashRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTlsJa3SHashTest01", DetectTlsJa3SHashTest01);
#endif /* UNITTESTS */
}

#endif /* HAVE_NSS */
