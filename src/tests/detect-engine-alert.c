/* Copyright (C) 2022 Open Information Security Foundation
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

#include "../suricata-common.h"

#include "../detect.h"
#include "../detect-engine.h"
#include "../detect-engine-alert.h"
#include "../detect-parse.h"

#include "../util-unittest.h"
#include "../util-unittest-helper.h"

#include "../counters.h"
#include "../detect-engine-build.h"
#include "../detect-engine-threshold.h"
#include "../util-time.h"

/** \brief Check if any queue entry still owns alert context.
 *
 * A queue entry owns context once it was never handed over to the packet, so
 * that context is leaked: PacketAlertFinalizeProcessQueue() does not look at
 * the entry again and the next packet overwrites the slot.
 */
static int AlertQueueOwnsContext(const DetectEngineThreadCtx *det_ctx)
{
    for (uint16_t i = 0; i < det_ctx->alert_queue_size; i++) {
        if (det_ctx->alert_queue[i].json_info != NULL) {
            return 1;
        }
    }
    return 0;
}

/** \brief Release the alert context the packet owns, as PacketReinit() does
 *        for pooled packets. Unit test packets are not recycled. */
static void PacketAlertsRelease(Packet *p)
{
    if (p->alerts.cnt > 0) {
        PacketAlertRecycle(p->alerts.alerts, p->alerts.cnt);
        p->alerts.cnt = 0;
    }
}

/**
 * \test Alerts the queue does not hand over to the packet must release the
 *       pcre `alert:` context they allocated for themselves. Here the alert is
 *       suppressed by a threshold rule, so it never reaches the packet and the
 *       packet side recycler cannot free it.
 */
static int TestDetectAlertQueueContextRelease01(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);
    ThresholdInit();

    uint8_t payload[] = "abc123";
    Packet *p = UTHBuildPacketReal(
            payload, sizeof(payload) - 1, IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 9999);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"alert context\"; content:\"abc\"; "
            "pcre:\"/abc([0-9]+)/,alert:captured\"; "
            "threshold: type limit, track by_src, count 1, seconds 3600; sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    /* first packet alerts: ownership moves to the packet. */
    p->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(p->alerts.cnt == 1);
    FAIL_IF_NULL(p->alerts.alerts[0].json_info);
    FAIL_IF(AlertQueueOwnsContext(det_ctx));
    PacketAlertsRelease(p);

    /* the rest is suppressed: the queue entries must own nothing. */
    for (int i = 0; i < 16; i++) {
        p->ts = TimeGet();
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
        FAIL_IF_NOT(p->alerts.cnt == 0);
        FAIL_IF_NOT(p->alerts.suppressed == 1);
        FAIL_IF(AlertQueueOwnsContext(det_ctx));
    }

    UTHFreePackets(&p, 1);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test A `pass` rule breaks out of the queue loop, so the entries behind it
 *       are never handled. Their context must not be left in the queue.
 */
static int TestDetectAlertQueueContextRelease02(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    uint8_t payload[] = "abc123";
    Packet *p = UTHBuildPacketReal(
            payload, sizeof(payload) - 1, IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 9999);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    /* Appended first, so that it lands behind the `pass` rule in the sorted
     * queue: a rule that is never reached is the point of the test. */
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any (msg:\"alert after pass\"; content:\"abc\"; "
            "pcre:\"/abc([0-9]+)/,alert:neverseen\"; sid:2; rev:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "pass udp any any -> any any (msg:\"pass with context\"; content:\"abc\"; "
            "pcre:\"/abc([0-9]+)/,alert:passed\"; sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    p->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* both rules match, the `pass` one is handled first and breaks out of the
     * loop, so the other one is dropped without reaching the packet. */
    FAIL_IF_NOT(det_ctx->alert_queue_size == 2);
    FAIL_IF_NOT(det_ctx->alert_queue[0].action & ACTION_PASS);
    FAIL_IF_NOT(p->alerts.cnt == 1);
    FAIL_IF_NOT(PacketAlertCheck(p, 2) == 0);
    FAIL_IF(AlertQueueOwnsContext(det_ctx));
    PacketAlertsRelease(p);

    UTHFreePackets(&p, 1);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \brief Tests that the reject action is correctly set in Packet->action
 */
static int TestDetectAlertPacketApplySignatureActions01(void)
{
#ifdef HAVE_LIBNET11
    uint8_t payload[] = "Hi all!";
    uint16_t length = sizeof(payload) - 1;
    Packet *p = UTHBuildPacketReal(
            (uint8_t *)payload, length, IPPROTO_TCP, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(p);

    const char sig[] = "reject tcp any any -> any 80 (content:\"Hi all\"; sid:1; rev:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);
    FAIL_IF_NOT(PacketTestAction(p, ACTION_REJECT_ANY));

    UTHFreePackets(&p, 1);
#endif /* HAVE_LIBNET11 */
    PASS;
}

/**
 * \brief Tests that the packet has the drop action correctly updated in Packet->action
 */
static int TestDetectAlertPacketApplySignatureActions02(void)
{
    uint8_t payload[] = "Hi all!";
    uint16_t length = sizeof(payload) - 1;
    Packet *p = UTHBuildPacketReal(
            (uint8_t *)payload, length, IPPROTO_TCP, "192.168.1.5", "192.168.1.1", 41424, 80);
    FAIL_IF_NULL(p);

    const char sig[] = "drop tcp any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    FAIL_IF(UTHPacketMatchSig(p, sig) == 0);
    FAIL_IF_NOT(PacketTestAction(p, ACTION_DROP));

    UTHFreePackets(&p, 1);
    PASS;
}

/**
 * \brief Registers Detect Engine Alert unit tests
 */
void DetectEngineAlertRegisterTests(void)
{
    UtRegisterTest("TestDetectAlertPacketApplySignatureActions01",
            TestDetectAlertPacketApplySignatureActions01);
    UtRegisterTest("TestDetectAlertPacketApplySignatureActions02",
            TestDetectAlertPacketApplySignatureActions02);
    UtRegisterTest("TestDetectAlertQueueContextRelease01", TestDetectAlertQueueContextRelease01);
    UtRegisterTest("TestDetectAlertQueueContextRelease02", TestDetectAlertQueueContextRelease02);
}
