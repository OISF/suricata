/* Copyright (C) 2015-2019 Open Information Security Foundation
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
 *
 * Set up of the "snmp.community" keyword to allow content
 * inspections on the decoded snmp community.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-snmp-community.h"
#include "app-layer-parser.h"

#include "rust-snmp-snmp-gen.h"
#include "rust-snmp-detect-gen.h"

static int DetectSNMPCommunitySetup(DetectEngineCtx *, Signature *,
    const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static void DetectSNMPCommunityRegisterTests(void);
static int g_snmp_rust_id = 0;

void DetectSNMPCommunityRegister(void)
{
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].name = "snmp.community";
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].desc =
        "SNMP content modififier to match on the SNMP community";
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].Setup =
        DetectSNMPCommunitySetup;
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].RegisterTests =
        DetectSNMPCommunityRegisterTests;
    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].url = DOC_URL DOC_VERSION "/rules/snmp-keywords.html#snmp.community";

    sigmatch_table[DETECT_AL_SNMP_COMMUNITY].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("snmp.community",
            ALPROTO_SNMP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("snmp.community", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_SNMP, 0);
    DetectAppLayerInspectEngineRegister2("snmp.community",
            ALPROTO_SNMP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("snmp.community", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_SNMP, 0);

    DetectBufferTypeSetDescriptionByName("snmp.community", "SNMP Community identifier");

    g_snmp_rust_id = DetectBufferTypeGetByName("snmp.community");
}

static int DetectSNMPCommunitySetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    if (DetectBufferSetActiveList(s, g_snmp_rust_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SNMP) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t data_len = 0;
        uint8_t *data = NULL;

        rs_snmp_tx_get_community(txv, (uint8_t **)&data, &data_len);
        if (data == NULL || data_len == 0) {
            return NULL;
        }

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "flow-util.h"
#include "stream-tcp.h"

static int DetectSNMPCommunityTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;
    Signature *s;

    /*uint8_t request[] = "\x30\x27\x02\x01\x01\x04\x0b\x5b\x52\x30\x5f\x43\x40\x63\x74\x69" \
                        "\x21\x5d\xa1\x15\x02\x04\x2b\x13\x3f\x85\x02\x01\x00\x02\x01\x00" \
                        "\x30\x07\x30\x05\x06\x01\x01\x05\x00";*/
    uint8_t request[] = {
        0x30, 0x27, 0x02, 0x01, 0x01, 0x04, 0x0b, 0x5b,
        0x52, 0x30, 0x5f, 0x43, 0x40, 0x63, 0x74, 0x69,
        0x21, 0x5d, 0xa1, 0x15, 0x02, 0x04, 0x2b, 0x13,
        0x3f, 0x85, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x07, 0x30, 0x05, 0x06, 0x01, 0x01, 0x05,
        0x00
    };

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    memset(&tv, 0, sizeof(ThreadVars));
    p = UTHBuildPacket(request, sizeof(request), IPPROTO_UDP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_SNMP;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    /* This rule should match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert snmp any any -> any any ("
        "msg:\"SNMP Test Rule\"; "
        "snmp.community; content:\"[R0_C@cti!]\"; "
        "sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    /* This rule should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert snmp any any -> any any ("
        "msg:\"SNMP Test Rule\"; "
        "snmp.community; content:\"private\"; "
        "sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SNMP,
                        STREAM_TOSERVER, request, sizeof(request));
    FLOWLOCK_UNLOCK(&f);

    /* Check that we have app-layer state. */
    FAIL_IF_NULL(f.alstate);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    /* Cleanup. */
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

#endif

static void DetectSNMPCommunityRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectSNMPCommunityTest",
        DetectSNMPCommunityTest);
#endif /* UNITTESTS */
}
