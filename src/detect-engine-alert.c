/* Copyright (C) 2007-2010 Open Information Security Foundation
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

/**
 * \brief Handle a packet and check if needs a threshold logic
 *
 * \param de_ctx Detection Context
 * \param sig Signature pointer
 * \param p Packet structure
 *
 */
int PacketAlertHandle(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                       Signature *s, Packet *p, uint16_t pos)
{
    SCEnter();
    int ret = 0;
    DetectThresholdData *td = NULL;

    /* retrieve the sig match data */
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        td = SigGetThresholdType(s,p);
    }

    SCLogDebug("td %p", td);

    /* if have none just alert, otherwise handle thresholding */
    if (td == NULL) {
        /* Already inserted so get out */
        ret = 1;
    } else {
        ret = PacketAlertThreshold(de_ctx, det_ctx, td, p, s);
        if (ret == 0) {
            /* It doesn't match threshold, remove it */
            PacketAlertRemove(p, pos);
        }
    }

    SCReturnInt(ret);
}


/**
 * \brief Check if a certain sid alerted, this is used in the test functions
 *
 * \param p   Packet on which we want to check if the signature alerted or not
 * \param sid Signature id of the signature that thas to be checked for a match
 *
 * \retval match A value > 0 on a match; 0 on no match
 */
int PacketAlertCheck(Packet *p, uint32_t sid)
{
    uint16_t i = 0;
    int match = 0;

    for (i = 0; i < p->alerts.cnt; i++) {
        if (p->alerts.alerts[i].sid == sid)
            match++;
    }

    return match;
}

/**
 * \brief Remove alert from the p->alerts.alerts array at pos
 * \param p Pointer to the Packet
 * \param pos Position in the array
 * \retval 0 if the number of alerts is less than pos
 *         1 if all goes well
 */
int PacketAlertRemove(Packet *p, uint16_t pos)
{
    uint16_t i = 0;
    int match = 0;
    if (pos > p->alerts.cnt)
        return 0;

    for (i = pos; i <= p->alerts.cnt - 1; i++) {
        memcpy(&p->alerts.alerts[i], &p->alerts.alerts[i + 1], sizeof(PacketAlert));
    }

    // Update it, since we removed 1
    p->alerts.cnt--;

    return match;
}

int PacketAlertAppend(DetectEngineThreadCtx *det_ctx, Signature *s, Packet *p)
{
    int i = 0;

    if (p->alerts.cnt == PACKET_ALERT_MAX)
        return 0;

    SCLogDebug("sid %"PRIu32"", s->id);

    /* It should be usually the last, so check it before iterating */
    if (p->alerts.cnt == 0 || (p->alerts.cnt > 0 &&
                               p->alerts.alerts[p->alerts.cnt - 1].order_id < s->order_id)) {
        /* We just add it */
        if (s->gid > 1)
            p->alerts.alerts[p->alerts.cnt].gid = s->gid;
        else
            p->alerts.alerts[p->alerts.cnt].gid = 1;

        p->alerts.alerts[p->alerts.cnt].num = s->num;
        p->alerts.alerts[p->alerts.cnt].order_id = s->order_id;
        p->alerts.alerts[p->alerts.cnt].action = s->action;
        p->alerts.alerts[p->alerts.cnt].sid = s->id;
        p->alerts.alerts[p->alerts.cnt].rev = s->rev;
        p->alerts.alerts[p->alerts.cnt].prio = s->prio;
        p->alerts.alerts[p->alerts.cnt].msg = s->msg;
        p->alerts.alerts[p->alerts.cnt].class = s->class;
        p->alerts.alerts[p->alerts.cnt].class_msg = s->class_msg;
        p->alerts.alerts[p->alerts.cnt].references = s->references;
    } else {
        /* We need to make room for this s->num
         (a bit ugly with mamcpy but we are planning changes here)*/
        for (i = p->alerts.cnt - 1; i >= 0 && p->alerts.alerts[i].order_id > s->order_id; i--) {
            memcpy(&p->alerts.alerts[i + 1], &p->alerts.alerts[i], sizeof(PacketAlert));
        }

        i++; /* The right place to store the alert */

        if (s->gid > 1)
            p->alerts.alerts[i].gid = s->gid;
        else
            p->alerts.alerts[i].gid = 1;

        p->alerts.alerts[i].num = s->num;
        p->alerts.alerts[i].order_id = s->order_id;
        p->alerts.alerts[i].action = s->action;
        p->alerts.alerts[i].sid = s->id;
        p->alerts.alerts[i].rev = s->rev;
        p->alerts.alerts[i].prio = s->prio;
        p->alerts.alerts[i].msg = s->msg;
        p->alerts.alerts[i].class = s->class;
        p->alerts.alerts[i].class_msg = s->class_msg;
        p->alerts.alerts[i].references = s->references;
    }

    /* Update the count */
    p->alerts.cnt++;

    return 0;
}

/**
 * \brief Fill the data of a tagged packet to be logged by unified
 */
int PacketAlertAppendTag(Packet *p, PacketAlert *pa)
{
        pa->sid = TAG_SIG_ID;
        pa->gid = TAG_SIG_GEN;
        pa->num = TAG_SIG_ID;
        pa->order_id = 1000;
        pa->action = ACTION_ALERT;
        pa->rev = 1;
        pa->prio = 2;
        pa->msg = NULL;
        pa->class = 0;
        pa->class_msg = NULL;
        pa->references = NULL;

    return 0;
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
void PacketAlertFinalize(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p) {
    SCEnter();

    int i = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;

    for (i = 0; i < p->alerts.cnt; i++) {
        SCLogDebug("Sig->num: %"PRIu16, p->alerts.alerts[i].num);
        s = de_ctx->sig_array[p->alerts.alerts[i].num];

        int res = PacketAlertHandle(de_ctx, det_ctx, s, p, i);
        /* Thresholding might remove one alert */
        if (res == 0) {
            i--;
        } else {
            /* Now, if we have an alert, we have to check if we want
             * to tag this session or src/dst host */
            sm = s->tmatch;
            while (sm) {
                /* tags are set only for alerts */
                sigmatch_table[sm->type].Match(NULL, det_ctx, p, s, sm);
                sm = sm->next;
            }

            if (s->flags & SIG_FLAG_IPONLY) {
                if ((p->flowflags & FLOW_PKT_TOSERVER && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
                    (p->flowflags & FLOW_PKT_TOCLIENT && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET))) {
                    SCLogDebug("testing against \"ip-only\" signatures");

                    if (p->flow != NULL) {
                        /* Update flow flags for iponly */
                        SCMutexLock(&p->flow->m);
                        FlowSetIPOnlyFlagNoLock(p->flow, p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0);

                        if (s->action & ACTION_DROP)
                            p->flow->flags |= FLOW_ACTION_DROP;
                        if (s->action & ACTION_REJECT)
                            p->flow->flags |= FLOW_ACTION_DROP;
                        if (s->action & ACTION_REJECT_DST)
                            p->flow->flags |= FLOW_ACTION_DROP;
                        if (s->action & ACTION_REJECT_BOTH)
                            p->flow->flags |= FLOW_ACTION_DROP;
                        if (s->action & ACTION_PASS)
                            p->flow->flags |= FLOW_ACTION_PASS;
                        SCMutexUnlock(&p->flow->m);
                    }
                }
            }

            /* set verdict on packet */
            p->action |= p->alerts.alerts[i].action;
            if (p->alerts.alerts[i].action & ACTION_PASS) {
                /* Ok, reset the alert cnt to end in the previous of pass
                 * so we ignore the rest with less prio */
                p->alerts.cnt = i;
                break;
            }
        }
        /* Because we removed the alert from the array, we should
         * have compacted the array and decreased cnt by one, so
         * process again the same position (with different alert now) */
    }

    /* At this point, we should have all the new alerts. Now check the tag
     * keyword context for sessions and hosts */
    TagHandlePacket(de_ctx, det_ctx, p);
}


