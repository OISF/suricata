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
#include "packet.h"

#include "flow.h"
#include "flow-private.h"

#ifdef DEBUG
#include "util-exception-policy.h"
#endif

#include "util-profiling.h"
#include "util-validate.h"

#include "action-globals.h"

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

/**
 * \brief Handle a packet and check if needs a threshold logic
 *        Also apply rule action if necessary.
 *
 * \param de_ctx Detection Context
 * \param sig Signature pointer
 * \param p Packet structure
 *
 * \retval 1 alert is not suppressed
 * \retval 0 alert is suppressed
 */
static int PacketAlertHandle(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                             const Signature *s, Packet *p, PacketAlert *pa)
{
    SCEnter();
    int ret = 1;
    const DetectThresholdData *td = NULL;
    const SigMatchData *smd;

    if (!(PacketIsIPv4(p) || PacketIsIPv6(p))) {
        SCReturnInt(1);
    }

    /* handle suppressions first */
    if (s->sm_arrays[DETECT_SM_LIST_SUPPRESS] != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_SUPPRESS);
        smd = NULL;
        do {
            td = SigGetThresholdTypeIter(s, &smd, DETECT_SM_LIST_SUPPRESS);
            if (td != NULL) {
                SCLogDebug("td %p", td);

                /* PacketAlertThreshold returns 2 if the alert is suppressed but
                 * we do need to apply rule actions to the packet. */
                KEYWORD_PROFILING_START;
                ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s, pa);
                if (ret == 0 || ret == 2) {
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

                /* PacketAlertThreshold returns 2 if the alert is suppressed but
                 * we do need to apply rule actions to the packet. */
                KEYWORD_PROFILING_START;
                ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s, pa);
                if (ret == 0 || ret == 2) {
                    KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD ,0);
                    /* It doesn't match threshold, remove it */
                    SCReturnInt(ret);
                }
                KEYWORD_PROFILING_END(det_ctx, DETECT_THRESHOLD, 1);
            }
        } while (smd != NULL);
    }
    SCReturnInt(1);
}

#ifdef UNITTESTS
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
    int match = 0;

    for (uint16_t i = 0; i < p->alerts.cnt; i++) {
        BUG_ON(p->alerts.alerts[i].s == NULL);
        if (p->alerts.alerts[i].s->id == sid)
            match++;
    }

    return match;
}
#endif

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

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable
 *  \param p packet
 *  \param s signature -- for id, sig pointer, not actions
 *  \param pa packet alert struct -- match, including actions after thresholding (rate_filter) */
static void PacketApplySignatureActions(Packet *p, const Signature *s, const PacketAlert *pa)
{
    SCLogDebug("packet %" PRIu64 " sid %u action %02x alert_flags %02x", p->pcap_cnt, s->id,
            pa->action, pa->flags);

    /* REJECT also sets ACTION_DROP, just make it more visible with this check */
    if (pa->action & ACTION_DROP_REJECT) {
        /* PacketDrop will update the packet action, too */
        PacketDrop(p, pa->action,
                (pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED) ? PKT_DROP_REASON_RULES_THRESHOLD
                                                                : PKT_DROP_REASON_RULES);
        SCLogDebug("[packet %p][DROP sid %u]", p, s->id);

        if (p->alerts.drop.action == 0) {
            p->alerts.drop.num = s->num;
            p->alerts.drop.action = pa->action;
            p->alerts.drop.s = (Signature *)s;
        }
        if ((p->flow != NULL) && (pa->flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(pa->action, p->flow);
        }

        DEBUG_VALIDATE_BUG_ON(!PacketCheckAction(p, ACTION_DROP));
    } else {
        if (pa->action & ACTION_PASS) {
            SCLogDebug("[packet %p][PASS sid %u]", p, s->id);
            // nothing to set in the packet
        } else if (pa->action & (ACTION_ALERT | ACTION_CONFIG)) {
            // nothing to set in the packet
        } else if (pa->action != 0) {
            DEBUG_VALIDATE_BUG_ON(1); // should be unreachable
        }

        if ((pa->action & ACTION_PASS) && (p->flow != NULL) &&
                (pa->flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(pa->action, p->flow);
        }
    }
}

void AlertQueueInit(DetectEngineThreadCtx *det_ctx)
{
    det_ctx->alert_queue_size = 0;
    det_ctx->alert_queue = SCCalloc(packet_alert_max, sizeof(PacketAlert));
    if (det_ctx->alert_queue == NULL) {
        FatalError("failed to allocate %" PRIu64 " bytes for the alert queue",
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

/** \internal
 */
static inline PacketAlert PacketAlertSet(
        DetectEngineThreadCtx *det_ctx, const Signature *s, uint64_t tx_id, uint8_t alert_flags)
{
    PacketAlert pa;
    pa.num = s->num;
    pa.action = s->action;
    pa.s = (Signature *)s;
    pa.flags = alert_flags;
    /* Set tx_id if the frame has it */
    pa.tx_id = tx_id;
    pa.frame_id = (alert_flags & PACKET_ALERT_FLAG_FRAME) ? det_ctx->frame_id : 0;
    pa.json_info.json_string = NULL;
    pa.json_info.next = NULL;
    if (det_ctx->json_content_len) {
        /* We have some JSON attached in the current detection so let's try
           to see if some need to be used for current signature. */
        struct JsonInfoList *current_json = &pa.json_info;
        for (size_t i = 0; i < det_ctx->json_content_len; i++) {
            if (s == det_ctx->json_content[i].id) {
                if (current_json->json_string != NULL) {
                    struct JsonInfoList *next_json = SCCalloc(1, sizeof(struct JsonInfoList));
                    if (next_json) {
                        current_json->next = next_json;
                        current_json = next_json;
                        current_json->next = NULL;
                    } else {
                        /* Allocation error, let's return now */
                        return pa;
                    }
                }
                current_json->json_string = det_ctx->json_content[i].json_content;
            }
        }
    }
    return pa;
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
    if (pa1->num == pa0->num) {
        if (pa1->tx_id == PACKET_ALERT_NOTX) {
            return -1;
        } else if (pa0->tx_id == PACKET_ALERT_NOTX) {
            return 1;
        }
        return pa0->tx_id < pa1->tx_id ? 1 : -1;
    }
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
    if (pa->action & (ACTION_DROP | ACTION_PASS)) {
        DEBUG_VALIDATE_BUG_ON(s->type == SIG_TYPE_NOT_SET);
        DEBUG_VALIDATE_BUG_ON(s->type == SIG_TYPE_MAX);

        enum SignaturePropertyFlowAction flow_action = signature_properties[s->type].flow_action;
        if (flow_action == SIG_PROP_FLOW_ACTION_FLOW) {
            pa->flags |= PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW;
        } else if (flow_action == SIG_PROP_FLOW_ACTION_FLOW_IF_STATEFUL) {
            if (pa->flags & (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_STREAM_MATCH)) {
                pa->flags |= PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW;
            }
        }

        if (pa->flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW) {
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

    for (uint16_t i = 0; i < det_ctx->alert_queue_size; i++) {
        PacketAlert *pa = &det_ctx->alert_queue[i];
        const Signature *s = de_ctx->sig_array[pa->num];
        int res = PacketAlertHandle(de_ctx, det_ctx, s, p, pa);
        if (res > 0) {
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
            FlowApplySignatureActions(p, pa, s, pa->flags);

            SCLogDebug("det_ctx->alert_queue[i].action %02x (DROP %s, PASS %s)", pa->action,
                    BOOL2STR(pa->action & ACTION_DROP), BOOL2STR(pa->action & ACTION_PASS));

            /* set actions on packet */
            PacketApplySignatureActions(p, s, pa);
        }

        /* Thresholding removes this alert */
        if (res == 0 || res == 2 || (s->action & (ACTION_ALERT | ACTION_PASS)) == 0) {
            SCLogDebug("sid:%u: skipping alert because of thresholding (res=%d) or NOALERT (%02x)",
                    s->id, res, s->action);
            /* we will not copy this to the AlertQueue */
            p->alerts.suppressed++;
        } else if (p->alerts.cnt < packet_alert_max) {
            p->alerts.alerts[p->alerts.cnt] = *pa;
            SCLogDebug("Appending sid %" PRIu32 " alert to Packet::alerts at pos %u", s->id, i);

            /* pass w/o alert found, we're done. Alert is not logged. */
            if ((pa->action & (ACTION_PASS | ACTION_ALERT)) == ACTION_PASS) {
                SCLogDebug("sid:%u: is a pass rule, so break out of loop", s->id);
                break;
            }
            p->alerts.cnt++;

            /* pass with alert, we're done. Alert is logged. */
            if (pa->action & ACTION_PASS) {
                SCLogDebug("sid:%u: is a pass rule, so break out of loop", s->id);
                break;
            }
        } else {
            p->alerts.discarded++;
        }
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
