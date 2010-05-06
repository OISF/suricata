#include "detect-engine-alert.h"
#include "suricata-common.h"
#include "detect.h"
#include "decode.h"

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
    if (pos >= p->alerts.cnt)
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
        p->alerts.alerts[i].class_msg = s->class_msg;
        p->alerts.alerts[i].references = s->references;
    }

    /* Update the count */
    p->alerts.cnt++;

    SCPerfCounterIncr(det_ctx->counter_alerts, det_ctx->tv->sc_perf_pca);

    return 0;
}

