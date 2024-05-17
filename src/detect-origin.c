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
#include "detect-origin.h"

static int DetectOriginMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectOriginSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectOriginFree(DetectEngineCtx *, void *);

#ifdef UNITTESTS
static void DetectOriginRegisterTests(void);
#endif

/**
 * \brief Registration function for origin: trusted/untrusted
 *
 * Only supporting roles of trusted/untrusted for faster matching.
 * The origin being trusted/untrusted refers to the originating
 * packet of a flow and the role of the live device for that packet.
 */
void DetectOriginRegister(void)
{
    sigmatch_table[DETECT_ORIGIN].name = "origin";
    sigmatch_table[DETECT_ORIGIN].desc = "Match the origin of the traffic based on the role "
                                         "(trusted/untrusted) of the interface.";
    sigmatch_table[DETECT_ORIGIN].Match = DetectOriginMatch;
    sigmatch_table[DETECT_ORIGIN].Setup = DetectOriginSetup;
    sigmatch_table[DETECT_ORIGIN].Free = DetectOriginFree;
    sigmatch_table[DETECT_ORIGIN].flags |= SIGMATCH_IPONLY_COMPAT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ORIGIN].RegisterTests = DetectOriginRegisterTests;
#endif
}

/**
 * \brief match origin role against a packet.
 *
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch context that we will cast into DetectOriginData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectOriginMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    DetectOriginData *originData = (DetectOriginData *)ctx;

    if (originData == NULL)
        return ret;

    if (p->flow && p->flow->livedev) {
        if (originData->role == p->flow->livedev->role) {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief load in the origin role to match against from signature.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current Signature
 * \param rolestr pointer to the user provided role options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectOriginSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rolestr)
{
    DetectOriginData *originData = NULL;

    originData = SCCalloc(1, sizeof(DetectOriginData));
    if (unlikely(originData == NULL))
        goto error;

    if (unlikely(rolestr == NULL))
        goto error;

    if (strncasecmp(rolestr, ROLE_TRUSTED_STR, strlen(ROLE_TRUSTED_STR)) == 0) {
        originData->role = ROLE_TRUSTED;
    } else if (strncasecmp(rolestr, ROLE_UNTRUSTED_STR, strlen(ROLE_UNTRUSTED_STR)) == 0) {
        originData->role = ROLE_UNTRUSTED;
    } else {
        SCLogError("Invalid Role: Origin keyword can only be used with roles \"trusted\" or "
                   "\"untrusted\".");
        goto error;
    }

    SigMatch *sm = SigMatchAppendSMToList(
            de_ctx, s, DETECT_ORIGIN, (SigMatchCtx *)originData, DETECT_SM_LIST_MATCH);
    if (sm == NULL) {
        goto error;
    }

    return 0;

error:
    if (originData != NULL)
        DetectOriginFree(de_ctx, originData);
    return -1;
}

/**
 * \brief free memory associated with OriginData
 *
 * \param ptr pointer to DetectOriginData
 */
void DetectOriginFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectOriginData *originData = (DetectOriginData *)ptr;
    SCFree(originData);
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

/* Confirm match when origin role matches */
static int DetectOriginTest01(void)
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

    LiveRegisterDevice("eth0", "trusted");

    p->livedev = LiveGetDevice("eth0");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->role != ROLE_TRUSTED);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"Test origin option\"; origin:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert, but it should have: ");
        FAIL;
    }

    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm no match when origin role doesn't match */
static int DetectOriginTest02(void)
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

    LiveRegisterDevice("eth1", "untrusted");

    p->livedev = LiveGetDevice("eth1");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->role != ROLE_UNTRUSTED);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"Test origin option\"; origin:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it shouldn't have: ");
        FAIL;
    }

    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm no match when no role for live device */
static int DetectOriginTest03(void)
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

    LiveRegisterDevice("eth2", "unknown");

    p->livedev = LiveGetDevice("eth2");
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    FAIL_IF(p->livedev->role != ROLE_UNKNOWN);

    f.livedev = p->livedev;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"Test origin option\"; origin:trusted; sid:1;)");

    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it shouldn't have: ");
        FAIL;
    }

    if (det_ctx != NULL) {
        StatsThreadCleanup(&tv);
        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/* Confirm device role is unknown when role is not trusted/untrusted */
static int DetectOriginTest04(void)
{
    LiveRegisterDevice("test1", "trusted");
    LiveRegisterDevice("test2", "untrusted");
    LiveRegisterDevice("test3", "home");

    LiveDevice *livedev = LiveGetDevice("test1");
    FAIL_IF(livedev->role != ROLE_TRUSTED);

    livedev = LiveGetDevice("test2");
    FAIL_IF(livedev->role != ROLE_UNTRUSTED);

    livedev = LiveGetDevice("test3");
    FAIL_IF(livedev->role != ROLE_UNKNOWN);

    PASS;
}

/* Confirm signature is not loaded when origin keyword is not trusted/untrusted */
static int DetectOriginTest05(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"Test origin option\"; origin: client; sid:1;)");

    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/* Confirm signature is not loaded when origin keyword is missing role */
static int DetectOriginTest06(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(
            de_ctx, "alert udp any any -> any any (msg:\"Test origin option\"; origin; sid:1;)");

    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static void DetectOriginRegisterTests(void)
{
    UtRegisterTest("DetectOriginTest01", DetectOriginTest01);
    UtRegisterTest("DetectOriginTest02", DetectOriginTest02);
    UtRegisterTest("DetectOriginTest03", DetectOriginTest03);
    UtRegisterTest("DetectOriginTest04", DetectOriginTest04);
    UtRegisterTest("DetectOriginTest05", DetectOriginTest05);
    UtRegisterTest("DetectOriginTest06", DetectOriginTest06);
}

#endif /* UNITTESTS */
