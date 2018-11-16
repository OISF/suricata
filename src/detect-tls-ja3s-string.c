/* Copyright (C) 2018 Open Information Security Foundation
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
 * Implements support for ja3s_string keyword.
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
#include "detect-tls-ja3s-string.h"

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

static int DetectTlsJa3SStringSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTlsJa3SStringRegisterTests(void);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *_f, const uint8_t _flow_flags,
       void *txv, const int list_id);
static int g_tls_ja3s_str_buffer_id = 0;

/**
 * \brief Registration function for keyword: ja3s_string
 */
void DetectTlsJa3SStringRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].name = "ja3s_string";
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].desc = "content modifier to match the JA3S string buffer";
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].url = DOC_URL DOC_VERSION "/rules/ja3-keywords.html#ja3s_string";
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].Setup = DetectTlsJa3SStringSetup;
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].Free = NULL;
    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].RegisterTests = DetectTlsJa3SStringRegisterTests;

    sigmatch_table[DETECT_AL_TLS_JA3S_STRING].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister2("ja3s_string", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("ja3s_string", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("ja3s_string", "TLS JA3S string");

    g_tls_ja3s_str_buffer_id = DetectBufferTypeGetByName("ja3s_string");
}

/**
 * \brief this function setup the ja3s_string modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0 On success
 */
static int DetectTlsJa3SStringSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectBufferSetActiveList(s, g_tls_ja3s_str_buffer_id);
    s->alproto = ALPROTO_TLS;

    if (RunmodeIsUnittests())
        return 0;

    /* Check if JA3 is disabled */
    if (Ja3IsDisabled("rule"))
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    BUG_ON(det_ctx->inspect_buffers == NULL);
    InspectionBuffer *buffer = &det_ctx->inspect_buffers[list_id];

    if (buffer->inspect == NULL) {
        SSLState *ssl_state = (SSLState *)_f->alstate;

        if (ssl_state->server_connp.ja3_str == NULL ||
                ssl_state->server_connp.ja3_str->data == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->server_connp.ja3_str->data);
        const uint8_t *data = (uint8_t *)ssl_state->server_connp.ja3_str->data;

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifndef HAVE_NSS

static void DetectTlsJa3SStringRegisterTests(void)
{
    /* Don't register any tests */
}

#else /* HAVE_NSS */

#ifdef UNITTESTS

/**
 * \test Test matching on a simple client hello packet
 */
static int DetectTlsJa3SStringTest01(void)
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
    Signature *s = NULL;
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

    s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test ja3s_hash\"; "
                              "ja3s_string; "
                              "content:\"771,49199,65281-0-35-16-11\"; "
                              "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                sizeof(client_hello));
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello, sizeof(server_hello));
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(r != 0);

    FAIL_IF_NULL(ssl_state->server_connp.ja3_str);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);

    PASS;
}

#endif /* UNITTESTS */

static void DetectTlsJa3SStringRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTlsJa3SStringTest01", DetectTlsJa3SStringTest01);
#endif /* UNITTESTS */
}

#endif /* HAVE_NSS */
