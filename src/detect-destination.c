/* Copyright (C) 2024 Open Information Security Foundation
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

#include "suricata-common.h"
#include "assert.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-destination.h"

static int DetectDestinationMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectDestinationSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectDestinationFree(DetectEngineCtx *, void *);

#ifdef UNITTESTS
static void DetectDestinationRegisterTests(void);
#endif

/**
 * \brief Registration function for destination: trusted/untrusted
 *
 * Only supporting roles of trusted/untrusted for faster matching.
 * The destination being trusted/untrusted refers to the packet of
 * a flow and the role of the live device that the packet is being
 * copied to.
 */
void DetectDestinationRegister(void)
{
    sigmatch_table[DETECT_DESTINATION].name = "destination";
    sigmatch_table[DETECT_DESTINATION].desc =
            "Match the destination of the traffic based on the role "
            "(trusted/untrusted) of the interface.";
    sigmatch_table[DETECT_DESTINATION].Match = DetectDestinationMatch;
    sigmatch_table[DETECT_DESTINATION].Setup = DetectDestinationSetup;
    sigmatch_table[DETECT_DESTINATION].Free = DetectDestinationFree;
    sigmatch_table[DETECT_DESTINATION].flags |= SIGMATCH_IPONLY_COMPAT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DESTINATION].RegisterTests = DetectDestinationRegisterTests;
#endif
}

/**
 * \brief match destination role against a packet.
 *
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch context that we will cast into DetectDestinationData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectDestinationMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectDestinationData *destination_data = (DetectDestinationData *)ctx;

    if (destination_data == NULL)
        return ret;

    if (p->flow && p->flow->livedev && p->flow->livedev->copy_dev) {
        if (destination_data->role == p->flow->livedev->copy_dev->role) {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief load in the destination role to match against from signature.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current Signature
 * \param rolestr pointer to the user provided role options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectDestinationSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rolestr)
{
    DetectDestinationData *destination_data = SCCalloc(1, sizeof(DetectDestinationData));
    if (unlikely(destination_data == NULL))
        goto error;

    if (unlikely(rolestr == NULL))
        goto error;

    if (strncmp(rolestr, ROLE_TRUSTED_STR, strlen(ROLE_TRUSTED_STR)) == 0) {
        destination_data->role = ROLE_TRUSTED;
    } else if (strncmp(rolestr, ROLE_UNTRUSTED_STR, strlen(ROLE_UNTRUSTED_STR)) == 0) {
        destination_data->role = ROLE_UNTRUSTED;
    } else {
        SCLogError("Invalid Role: Destination keyword can only be used with roles \"trusted\" or "
                   "\"untrusted\".");
        goto error;
    }

    SigMatch *sm = SigMatchAppendSMToList(
            de_ctx, s, DETECT_DESTINATION, (SigMatchCtx *)destination_data, DETECT_SM_LIST_MATCH);
    if (sm == NULL) {
        goto error;
    }

    return 0;

error:
    if (destination_data != NULL)
        DetectDestinationFree(de_ctx, destination_data);
    return -1;
}

/**
 * \brief free memory associated with DestinationData
 *
 * \param ptr pointer to DetectDestinationData
 */
void DetectDestinationFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectDestinationData *destination_data = (DetectDestinationData *)ptr;
    SCFree(destination_data);
}

#ifdef UNITTESTS
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-dns-query.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"

/* Confirm match when destination role matches */
static int DetectDestinationTest01(void)
{
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t *buf = (uint8_t *)"supernovaduper";

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;

    LiveRegisterDevice("dest0", "trusted");
    LiveRegisterDevice("dest1", "trusted");

    p->livedev = LiveGetDevice("dest0");
    p->livedev->copy_dev = LiveGetDevice("dest1");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->copy_dev->role != ROLE_TRUSTED);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any (msg:\"Test destination "
                                      "option\"; destination:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    StatsThreadCleanup(&tv);
    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm no match when destination role doesn't match */
static int DetectDestinationTest02(void)
{
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t *buf = (uint8_t *)"supernovaduper";

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;

    LiveRegisterDevice("dest2", "trusted");
    LiveRegisterDevice("dest3", "untrusted");

    p->livedev = LiveGetDevice("dest2");
    p->livedev->copy_dev = LiveGetDevice("dest3");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->copy_dev->role != ROLE_UNTRUSTED);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any (msg:\"Test destination "
                                      "option\"; destination:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    StatsThreadCleanup(&tv);
    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm no match when no role for live device */
static int DetectDestinationTest03(void)
{
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t *buf = (uint8_t *)"supernovaduper";

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;

    LiveRegisterDevice("dest4", "trusted");
    LiveRegisterDevice("dest5", "unknown");

    p->livedev = LiveGetDevice("dest4");
    p->livedev->copy_dev = LiveGetDevice("dest5");

    p->livedev = LiveGetDevice("dest4");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->copy_dev->role != ROLE_UNKNOWN);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any (msg:\"Test destination "
                                      "option\"; destination:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    StatsThreadCleanup(&tv);
    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm signature is not loaded when destination keyword is not trusted/untrusted */
static int DetectDestinationTest04(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any (msg:\"Test destination "
                                      "option\"; destination: client; sid:1;)");

    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/* Confirm signature is not loaded when destination keyword is missing role */
static int DetectDestinationTest05(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"Test destination option\"; destination; sid:1;)");

    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static void DetectDestinationRegisterTests(void)
{
    UtRegisterTest("DetectDestinationTest01", DetectDestinationTest01);
    UtRegisterTest("DetectDestinationTest02", DetectDestinationTest02);
    UtRegisterTest("DetectDestinationTest03", DetectDestinationTest03);
    UtRegisterTest("DetectDestinationTest04", DetectDestinationTest04);
    UtRegisterTest("DetectDestinationTest05", DetectDestinationTest05);
}
#endif /* UNITTESTS */
