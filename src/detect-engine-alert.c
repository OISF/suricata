/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "detect.h"
#include "detect-engine-alert.h"
#include "detect-engine-threshold.h"
#include "detect-engine-tag.h"

#include "decode.h"

#include "flow.h"
#include "flow-private.h"

#ifdef DEBUG
#include "util-exception-policy.h"
#endif

#include "util-profiling.h"
#include "util-validate.h"

/** tag signature we use for tag alerts */
static Signature g_tag_signature;
/** tag packet alert structure for tag alerts */
static PacketAlert g_tag_pa;

void PacketAlertTagInit(void)
{
    memset(&g_tag_signature, 0x00, sizeof(g_tag_signature));

    g_tag_signature.id = TAG_SIG_ID;
    g_tag_signature.gid = TAG_SIG_GEN;
    g_tag_signature.num = TAG_SIG_ID;
    g_tag_signature.rev = 1;
    g_tag_signature.prio = 2;

    memset(&g_tag_pa, 0x00, sizeof(g_tag_pa));

    g_tag_pa.action = ACTION_ALERT;
    g_tag_pa.s = &g_tag_signature;
}

PacketAlert *PacketAlertGetTag(void)
{
    return &g_tag_pa;
}

/**
 * \brief Handle a packet and check if needs a threshold logic
 *        Also apply rule action if necessary.
 *
 * \param de_ctx Detection Context
 * \param sig Signature pointer
 * \param p Packet structure
 *
 * \retval THRESHOLD_NOT_SUPPRESSED alert is not suppressed
 * \retval THRESHOLD_SUPPRESSED alert is suppressed
 */
static SigThresholdResults PacketAlertHandle(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p, PacketAlert *pa)
{
    SCEnter();
    SigThresholdResults ret = THRESHOLD_NOT_SUPPRESSED;
    const DetectThresholdData *td = NULL;
    const SigMatchData *smd;

    if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
        SCReturnInt(THRESHOLD_NOT_SUPPRESSED);
    }

    /* handle suppressions first */
    if (s->sm_arrays[DETECT_SM_LIST_SUPPRESS] != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_SUPPRESS);
        smd = NULL;
        do {
            td = SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_SUPPRESS);
            if (td != NULL) {
                SCLogDebug("td %p", td);

                /* PacketAlertThreshold returns THRESHOLD_SILENT_MATCH if the alert is suppressed
                 * but we do need to apply rule actions to the packet. */
                KEYWORD_PROFILING_START;
                ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s, pa);
                if (ret == THRESHOLD_SUPPRESSED || ret == THRESHOLD_SILENT_MATCH) {
                    KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD, 0);
                    /* It doesn't match threshold, remove it */
                    SCReturnInt(ret);
                }
                KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD, 1);
            }
        } while (smd != NULL);
    }

    /* if we're still here, consider thresholding */
    if (s->sm_arrays[DETECT_SM_LIST_THRESHOLD] != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_THRESHOLD);
        smd = NULL;
        do {
            td = SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_THRESHOLD);
            if (td != NULL) {
                SCLogDebug("td %p", td);

                /* PacketAlertThreshold returns THRESHOLD_SILENT_MATCH if the alert is suppressed
                 * but we do need to apply rule actions to the packet. */
                KEYWORD_PROFILING_START;
                ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s, pa);
                if (ret == THRESHOLD_SUPPRESSED || ret == THRESHOLD_SILENT_MATCH) {
                    KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD ,0);
                    /* It doesn't match threshold, remove it */
                    SCReturnInt(ret);
                }
                KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD, 1);
            }
        } while (smd != NULL);
    }
    SCReturnInt(THRESHOLD_NOT_SUPPRESSED);
}

/**
 * \brief Check if a certain sid alerted, this is used in the test functions
 *
 * \param p   Packet on which we want to check if the signature alerted or not
 * \param sid Signature id of the signature that has to be checked for a match
 *
 * \retval match A value > 0 on a match; 0 on no match
 */
int PacketAlertCheck(Packet *p, uint32_t sid)
{
    uint16_t i = 0;
    int match = 0;

    for (i = 0; i < p->alerts.cnt; i++) {
        if (p->alerts.alerts[i].s == NULL)
            continue;

        if (p->alerts.alerts[i].s->id == sid)
            match++;
    }

    return match;
}

static inline void RuleActionToFlow(const uint8_t action, Flow *f)
{
    if (action & (ACTION_DROP | ACTION_REJECT_ANY | ACTION_PASS)) {
        if (f->flags & (FLOW_ACTION_DROP | FLOW_ACTION_PASS)) {
            /* drop or pass already set. First to set wins. */
            SCLogDebug("not setting %s flow already set to %s",
                    (action & ACTION_PASS) ? "pass" : "drop",
                    (f->flags & FLOW_ACTION_DROP) ? "drop" : "pass");
        } else {
            if (action & (ACTION_DROP | ACTION_REJECT_ANY)) {
                f->flags |= FLOW_ACTION_DROP;
                SCLogDebug("setting flow action drop");
            }
            if (action & ACTION_PASS) {
                f->flags |= FLOW_ACTION_PASS;
                SCLogDebug("setting flow action pass");
                FlowSetNoPacketInspectionFlag(f);
            }
        }
    }
}

/** \internal
 */
static inline PacketAlert PacketAlertSet(
        DetectEngineThreadCtx *det_ctx, const Signature *s, uint64_t tx_id, uint8_t alert_flags)
{
    PacketAlert pa = { s->num, s->action, alert_flags, s, tx_id, 0 };
    pa.num = s->num;
    pa.action = s->action;
    pa.s = (Signature *)s;
    pa.flags = alert_flags;
    /* Set tx_id if the frame has it */
    pa.tx_id = (tx_id == UINT64_MAX) ? 0 : tx_id;
    pa.frame_id = (alert_flags & PACKET_ALERT_FLAG_FRAME) ? det_ctx->frame_id : 0;
    return pa;
}

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable */
static void PacketApplySignatureActions(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const uint8_t alert_flags)
{
    SCLogDebug("packet %" PRIu64 " sid %u action %02x alert_flags %02x", p->pcap_cnt, s->id,
            s->action, alert_flags);

    /* REJECT also sets ACTION_DROP, just make it more visible with this check */
    if (s->action & (ACTION_DROP | ACTION_REJECT_ANY)) {
        /* PacketDrop will update the packet action, too */
        PacketDrop(p, s->action, PKT_DROP_REASON_RULES);

        if (p->alerts.drop.action == 0) {
            p->alerts.drop = PacketAlertSet(det_ctx, s, 0, alert_flags);
        }
        if ((p->flow != NULL) && (alert_flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(s->action, p->flow);
        }

        DEBUG_VALIDATE_BUG_ON(!PacketTestAction(p, ACTION_DROP));
    } else {
        PacketUpdateAction(p, s->action);

        if ((s->action & ACTION_PASS) && (p->flow != NULL) &&
                (alert_flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(s->action, p->flow);
        }
    }
}

void AlertQueueInit(DetectEngineThreadCtx *det_ctx)
{
    det_ctx->alert_queue_size = 0;
    det_ctx->alert_queue = SCCalloc(packet_alert_max, sizeof(PacketAlert));
    if (det_ctx->alert_queue == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to allocate %" PRIu64 " bytes for the alert queue",
                (uint64_t)(packet_alert_max * sizeof(PacketAlert)));
    }
    det_ctx->alert_queue_capacity = packet_alert_max;
    SCLogDebug("alert queue initialized to %u elements (%" PRIu64 " bytes)", packet_alert_max,
            (uint64_t)(packet_alert_max * sizeof(PacketAlert)));
}

void AlertQueueFree(DetectEngineThreadCtx *det_ctx)
{
    SCFree(det_ctx->alert_queue);
    det_ctx->alert_queue_capacity = 0;
}

/** \internal
 * \retval the new capacity
 */
static uint16_t AlertQueueExpand(DetectEngineThreadCtx *det_ctx)
{
#ifdef DEBUG
    if (unlikely(g_eps_is_alert_queue_fail_mode))
        return det_ctx->alert_queue_capacity;
#endif
    uint16_t new_cap = det_ctx->alert_queue_capacity * 2;
    void *tmp_queue = SCRealloc(det_ctx->alert_queue, (size_t)(sizeof(PacketAlert) * new_cap));
    if (unlikely(tmp_queue == NULL)) {
        /* queue capacity didn't change */
        return det_ctx->alert_queue_capacity;
    }
    det_ctx->alert_queue = tmp_queue;
    det_ctx->alert_queue_capacity = new_cap;
    SCLogDebug("Alert queue size doubled: %u elements, bytes: %" PRIuMAX "",
            det_ctx->alert_queue_capacity,
            (uintmax_t)(sizeof(PacketAlert) * det_ctx->alert_queue_capacity));
    return new_cap;
}

/**
 * \brief Append signature to local packet alert queue for later preprocessing
 */
void AlertQueueAppend(DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p, uint64_t tx_id,
        uint8_t alert_flags)
{
    /* first time we see a drop action signature, set that in the packet */
    /* we do that even before inserting into the queue, so we save it even if appending fails */
    if (p->alerts.drop.action == 0 && s->action & ACTION_DROP) {
        p->alerts.drop = PacketAlertSet(det_ctx, s, tx_id, alert_flags);
        SCLogDebug("Set PacketAlert drop action. s->num %" PRIu32 "", s->num);
    }

    uint16_t pos = det_ctx->alert_queue_size;
    if (pos == det_ctx->alert_queue_capacity) {
        /* we must grow the alert queue */
        if (pos == AlertQueueExpand(det_ctx)) {
            /* this means we failed to expand the queue */
            p->alerts.discarded++;
            return;
        }
    }
    det_ctx->alert_queue[pos] = PacketAlertSet(det_ctx, s, tx_id, alert_flags);

    SCLogDebug("Appending sid %" PRIu32 ", s->num %" PRIu32 " to alert queue", s->id, s->num);
    det_ctx->alert_queue_size++;
    return;
}

/** \internal
 * \brief sort helper for sorting alerts by priority
 *
 * Sorting is done first based on num and then using tx_id, if nums are equal.
 * The Signature::num field is set based on internal priority. Higher priority
 * rules have lower nums.
 */
static int AlertQueueSortHelper(const void *a, const void *b)
{
    const PacketAlert *pa0 = a;
    const PacketAlert *pa1 = b;
    if (pa1->num == pa0->num)
        return pa0->tx_id < pa1->tx_id ? 1 : -1;
    else
        return pa0->num > pa1->num ? 1 : -1;
}

/** \internal
 * \brief Check if Signature action should be applied to flow and apply
 *
 */
static inline void FlowApplySignatureActions(
        Packet *p, PacketAlert *pa, const Signature *s, uint8_t alert_flags)
{
    /* For DROP and PASS sigs we need to apply the action to the flow if
     * - sig is IP or PD only
     * - match is in applayer
     * - match is in stream */
    if (s->action & (ACTION_DROP | ACTION_PASS)) {
        if ((pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_STREAM_MATCH)) ||
                (s->flags & (SIG_FLAG_IPONLY | SIG_FLAG_LIKE_IPONLY | SIG_FLAG_PDONLY |
                                    SIG_FLAG_APPLAYER))) {
            pa->flags |= PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW;
            SCLogDebug("packet %" PRIu64 " sid %u action %02x alert_flags %02x (set "
                       "PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)",
                    p->pcap_cnt, s->id, s->action, pa->flags);
        }
    }
}

/**
 * \brief Check the threshold of the sigs that match, set actions, break on pass action
 *        This function iterate the packet alerts array, removing those that didn't match
 *        the threshold, and those that match after a signature with the action "pass".
 *        The array is sorted by action priority/order
 * \param de_ctx detection engine context
 * \param det_ctx detection engine thread context
 * \param p pointer to the packet
 */
void PacketAlertFinalize(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    SCEnter();

    /* sort the alert queue before thresholding and appending to Packet */
    qsort(det_ctx->alert_queue, det_ctx->alert_queue_size, sizeof(PacketAlert),
            AlertQueueSortHelper);

    uint16_t i = 0;
    uint16_t max_pos = det_ctx->alert_queue_size;

    while (i < max_pos) {
        const Signature *s = de_ctx->sig_array[det_ctx->alert_queue[i].num];
        int res = PacketAlertHandle(de_ctx, det_ctx, s, p, &det_ctx->alert_queue[i]);

        if (res > THRESHOLD_DONT_ALERT) {
            /* Now, if we have an alert, we have to check if we want
             * to tag this session or src/dst host */
            if (s->sm_arrays[DETECT_SM_LIST_TMATCH] != NULL) {
                KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_TMATCH);
                SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_TMATCH];
                while (1) {
                    /* tags are set only for alerts */
                    KEYWORD_PROFILING_START;
                    sigmatch_table[smd->type].Match(det_ctx, p, (Signature *)s, smd->ctx);
                    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                    if (smd->is_last)
                        break;
                    smd++;
                }
            }

            /* set actions on the flow */
            FlowApplySignatureActions(
                    p, &det_ctx->alert_queue[i], s, det_ctx->alert_queue[i].flags);

            /* set actions on packet */
            PacketApplySignatureActions(det_ctx, p, s, det_ctx->alert_queue[i].flags);
        }

        /* Thresholding removes this alert */
        if (res == THRESHOLD_SUPPRESSED || res == THRESHOLD_SILENT_MATCH ||
                (s->flags & SIG_FLAG_NOALERT)) {
            /* we will not copy this to the AlertQueue */
            p->alerts.suppressed++;
        } else if (p->alerts.cnt < packet_alert_max) {
            p->alerts.alerts[p->alerts.cnt] = det_ctx->alert_queue[i];
            SCLogDebug("Appending sid %" PRIu32 " alert to Packet::alerts at pos %u", s->id, i);

            if (PacketTestAction(p, ACTION_PASS)) {
                /* Ok, reset the alert cnt to end in the previous of pass
                 * so we ignore the rest with less prio */
                break;
            }
            p->alerts.cnt++;
        } else {
            p->alerts.discarded++;
        }
        i++;
    }

    /* At this point, we should have all the new alerts. Now check the tag
     * keyword context for sessions and hosts */
    if (!(p->flags & PKT_PSEUDO_STREAM_END))
        TagHandlePacket(de_ctx, det_ctx, p);

    /* Set flag on flow to indicate that it has alerts */
    if (p->flow != NULL && p->alerts.cnt > 0) {
        if (!FlowHasAlerts(p->flow)) {
            FlowSetHasAlertsFlag(p->flow);
            p->flags |= PKT_FIRST_ALERTS;
        }
    }
}

#ifdef UNITTESTS
#include "tests/detect-engine-alert.c"
#endif
