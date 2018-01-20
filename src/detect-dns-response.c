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
 * \ingroup dnslayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Stian Bergseth <stianb@mnemonic.no>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-dns-common.h"
#include "detect-dns-response.h"
#include "detect-engine-dns.h"

#include "util-unittest-helper.h"

static int DetectDnsResponseSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectDnsResponseRegisterTests(void);
static int g_dns_response_buffer_id = 0;

void DetectDnsResponseRegister (void)
{
    sigmatch_table[DETECT_AL_DNS_RESPONSE].name = "dns_response";
    sigmatch_table[DETECT_AL_DNS_RESPONSE].desc = "content modifier to match DNS responses in a binary format";
    sigmatch_table[DETECT_AL_DNS_RESPONSE].Match = NULL;
    sigmatch_table[DETECT_AL_DNS_RESPONSE].Setup = DetectDnsResponseSetup;
    sigmatch_table[DETECT_AL_DNS_RESPONSE].Free  = NULL;
    sigmatch_table[DETECT_AL_DNS_RESPONSE].RegisterTests = DetectDnsResponseRegisterTests;

    sigmatch_table[DETECT_AL_DNS_RESPONSE].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister("dns_response", SIG_FLAG_TOCLIENT, 2,
        PrefilterTxDnsResponseRegister);
        

    DetectAppLayerInspectEngineRegister("dns_response",
            ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectDnsResponse);

    g_dns_response_buffer_id = DetectBufferTypeGetByName("dns_response");

    DetectBufferTypeSetDescriptionByName("dns_response",
            "dns response");
    
    /* register these generic engines from here for now */
    DetectAppLayerInspectEngineRegister("dns_response_generic",
            ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectDnsResponseGeneric);
    DetectBufferTypeSetDescriptionByName("dns_response_generic",
            "dns responses_generic");

}

/**
 * \brief this function setups the dns_response modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 */

static int DetectDnsResponseSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    s->init_data->list = g_dns_response_buffer_id;
    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0) {
        return -1;
    }
    return 0;
}

#ifdef UNITTESTS

/** \test simple dns response match on A record */
static int DetectDnsResponseTest01(void)
{
   uint8_t buf[] = {
            0x00, 0x01, // tx id
            0x81, 0x80, // response flags (response recursion desired + available)
            0x00, 0x01, // nr of questions
            0x00, 0x01, // answer RRs
            0x00, 0x00, // authority RR
            0x00, 0x00, // additional RRs
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00, // google.com
            0x00, 0x01, // A Type
            0x00, 0x01, // Class
            0xC0, 0x0C,
            0x00, 0x01, // A type
            0x00, 0x01, // Class
            0x00, 0x00, 0x00, 0xFF, // TTL
            0x00, 0x04, // Length
            0xAC, 0xD9, 0x12, 0x8E, // 172.217.18.142
        };

    Flow f;
    DNSState *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP,
                           "192.168.1.1", "192.168.1.5",
                           53, 41424);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert dns any any -> any any "
                              "(msg:\"Test dns_query option\"; "
                              "dns_response; content:\"|AC D9 12 8E|\"; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOCLIENT, buf, sizeof(buf));

    FAIL_IF(r != 0);

    FLOWLOCK_UNLOCK(&f);

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;

}
#endif

static void DetectDnsResponseRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDnsResponseTest01", DetectDnsResponseTest01);
#endif
};
