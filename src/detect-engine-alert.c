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

#include "util-profiling.h"
#include "util-validate.h" //DEBUG_VALIDATE_BUG_ON

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

    if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
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

/**
 * \brief Remove alert from the p->alerts.alerts array at pos
 * \param p Pointer to the Packet
 * \param pos Position in the array
 */
static void PacketAlertRemove(Packet *p, uint16_t pos)
{
    if (pos >= p->alerts.cnt) {
        SCLogDebug("removing %u failed, pos > cnt %u", pos, p->alerts.cnt);
        return;
    }

    const uint16_t after = (p->alerts.cnt - 1) - pos;
    if (after) {
        const uint16_t after_start = pos + 1;
        memmove(p->alerts.alerts + pos, p->alerts.alerts + after_start,
                (sizeof(PacketAlert) * after));
    }

    p->alerts.cnt--;
}

/**
 * \brief calculate correct position for alert queue insertion, do memmove if needed
 *
 * \param p packet
 * \param s matched signature
 * \retval int16_t index of position for insertion in the alert queue
 */
static uint16_t PacketAlertMemMoveQueuePos(Packet *p, const Signature *s)
{
    uint16_t i = 0;
    for (i = p->alerts.cnt; i > 0 && p->alerts.alerts[i - 1].num > s->num; i--)
        ;

    const uint16_t target_pos = i + 1;
    /* There is no space left for memmove, let's just replace*/
    if (target_pos == packet_alert_max) {
        return i;
    }
    const uint16_t space_post_target = packet_alert_max - 1 - i;
    const uint16_t to_move = MIN(space_post_target, (p->alerts.cnt - i));
    DEBUG_VALIDATE_BUG_ON(to_move == 0);
    memmove(p->alerts.alerts + target_pos, p->alerts.alerts + i, (to_move * sizeof(PacketAlert)));

    /* We'll use i later on to insert the alert in the Packet Queue*/
    return i;
}

/**
 * \brief insert signature in packet alerts queue
 *
 * After logic for appending at the right position is applied, just call this to
 * insert at the right position.
 *
 * \param det_ctx thread detection engine ctx
 * \param s the signature that matched
 * \param p packet
 * \param flags alert flags
 * \param pos the correct position in the Alerts queue
 */
static void PacketAlertInsertPos(DetectEngineThreadCtx *det_ctx, const Signature *s, Packet *p,
        uint64_t tx_id, uint8_t flags, uint16_t pos)
{
    p->alerts.alerts[pos].num = s->num;
    p->alerts.alerts[pos].action = s->action;
    p->alerts.alerts[pos].flags = flags;
    p->alerts.alerts[pos].s = s;
    p->alerts.alerts[pos].tx_id = tx_id;
    p->alerts.alerts[pos].frame_id = (flags & PACKET_ALERT_FLAG_FRAME) ? det_ctx->frame_id : 0;
}

/** \brief append a signature match to a packet
 *
 *  \param det_ctx thread detection engine ctx
 *  \param s the signature that matched
 *  \param p packet
 *  \param flags alert flags
 */
int PacketAlertAppend(DetectEngineThreadCtx *det_ctx, const Signature *s,
        Packet *p, uint64_t tx_id, uint8_t flags)
{
    SCLogDebug("sid %" PRIu32 "", s->id);

    /* highly unlikely, but seems better to check */
    BUG_ON(p->alerts.cnt > packet_alert_max);

    if (p->alerts.cnt < packet_alert_max) {
        /* It should be usually the last, so check it before iterating */
        /* Same signatures can generate more than one alert, if it's a diff tx */
        if (p->alerts.cnt == 0 || p->alerts.alerts[p->alerts.cnt - 1].num <= s->num) {
            /* We just add it */
            PacketAlertInsertPos(det_ctx, s, p, tx_id, flags, p->alerts.cnt);
            SCLogDebug("Added signature %" PRIu32 " internal id %" PRIu32 " to packet %" PRIu64 "",
                    s->id, s->num, p->pcap_cnt);
        } else {
            /* find position to insert */
            uint16_t i = PacketAlertMemMoveQueuePos(p, s);
            PacketAlertInsertPos(det_ctx, s, p, tx_id, flags, i);
            SCLogDebug("Added signature %" PRIu32 " to packet %" PRIu64 "", s->id, p->pcap_cnt);
        }

        /* Update the count */
        p->alerts.cnt++;
    } else {
        SCLogDebug("Reached packet_alert_max.");
        /* If we reach packet_alert_max, remove lower priority
         * rules and keep newer, higher priority ones.
         * If Suri wants to append a signature whose priority is lower than the
         * ones already queued and we are at packet_alert_max, it isn't queued. */

        int16_t num_diff = s->num - p->alerts.alerts[p->alerts.cnt - 1].num;
        if (num_diff == 0 || num_diff == -1) {
            /* Replace last position in queue */
            SCLogDebug("Replacing lower priority signature %" PRIu32 " (%" PRIu32
                       ")  with higher priority signature %" PRIu32 " (%" PRIu32
                       ") in packet %" PRIu64 "",
                    p->alerts.alerts[p->alerts.cnt - 1].s->id,
                    p->alerts.alerts[p->alerts.cnt - 1].num, s->id, s->num, p->pcap_cnt);
            // TODO log to stats signature id that was discarded/replaced
            PacketAlertInsertPos(det_ctx, s, p, tx_id, flags, (p->alerts.cnt - 1));
        } else if (num_diff < -1) {
            /* If the new signature's internal id isn't equal/adjacent to the last one from the
             * queue, find the correct position, to keep queue sorted by rule priority */
            uint16_t i = PacketAlertMemMoveQueuePos(p, s);
            SCLogDebug("Replacing lower priority signature %" PRIu32 " (%" PRIu32
                       ") with higher priority signature %" PRIu32 " (%" PRIu32
                       ") in packet %" PRIu64 "",
                    p->alerts.alerts[i].s->id, p->alerts.alerts[i].num, s->id, s->num, p->pcap_cnt);
            PacketAlertInsertPos(det_ctx, s, p, tx_id, flags, i);
            // TODO log to stats signature id that was discarded/replaced
        }
        /* Do not update p->alerts.cnt here, already at max */
        // TODO how do we take care of alerts that have drop action, in this case?
    }

    return 0;
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

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable */
static void PacketApplySignatureActions(Packet *p, const Signature *s, const uint8_t alert_flags)
{
    SCLogDebug("packet %" PRIu64 " sid %u action %02x alert_flags %02x", p->pcap_cnt, s->id,
            s->action, alert_flags);
    PacketUpdateAction(p, s->action);

    if (s->action & ACTION_DROP) {
        if (p->alerts.drop.action == 0) {
            p->alerts.drop.num = s->num;
            p->alerts.drop.action = s->action;
            p->alerts.drop.s = (Signature *)s;
        }
        if ((p->flow != NULL) && (alert_flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(s->action, p->flow);
        }
    } else if (s->action & ACTION_PASS) {
        if ((p->flow != NULL) && (alert_flags & PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)) {
            RuleActionToFlow(s->action, p->flow);
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
    int i = 0;

    while (i < p->alerts.cnt) {
        const Signature *s = de_ctx->sig_array[p->alerts.alerts[i].num];
        SCLogDebug("Sig->num: %" PRIu32 " SID %u", p->alerts.alerts[i].num, s->id);

        int res = PacketAlertHandle(de_ctx, det_ctx, s, p, &p->alerts.alerts[i]);
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

            /* For DROP and PASS sigs we need to apply the action to the flow if
             * - sig is IP or PD only
             * - match is in applayer
             * - match is in stream */
            if (s->action & (ACTION_DROP | ACTION_PASS)) {
                if ((p->alerts.alerts[i].flags &
                            (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_STREAM_MATCH)) ||
                        (s->flags & (SIG_FLAG_IPONLY | SIG_FLAG_PDONLY | SIG_FLAG_APPLAYER))) {
                    p->alerts.alerts[i].flags |= PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW;
                    SCLogDebug("packet %" PRIu64 " sid %u action %02x alert_flags %02x (set "
                               "PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW)",
                            p->pcap_cnt, s->id, s->action, p->alerts.alerts[i].flags);
                }
            }

            /* set actions on packet */
            PacketApplySignatureActions(p, p->alerts.alerts[i].s, p->alerts.alerts[i].flags);

            if (PacketTestAction(p, ACTION_PASS)) {
                /* Ok, reset the alert cnt to end in the previous of pass
                 * so we ignore the rest with less prio */
                p->alerts.cnt = i;
                break;
            }
        }

        /* Thresholding removes this alert */
        if (res == 0 || res == 2 || (s->flags & SIG_FLAG_NOALERT)) {
            PacketAlertRemove(p, i);

            if (p->alerts.cnt == 0)
                break;
        } else {
            i++;
        }
    }

    /* At this point, we should have all the new alerts. Now check the tag
     * keyword context for sessions and hosts */
    if (!(p->flags & PKT_PSEUDO_STREAM_END))
        TagHandlePacket(de_ctx, det_ctx, p);

    /* Set flag on flow to indicate that it has alerts */
    if (p->flow != NULL && p->alerts.cnt > 0) {
        FlowSetHasAlertsFlag(p->flow);
    }
}
