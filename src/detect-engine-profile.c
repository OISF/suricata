/* Copyright (C) 2016-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "detect-engine-profile.h"

#ifdef PROFILING
#include "output-json.h"
#include "util-conf.h"

SCMutex g_rule_dump_write_m = SCMUTEX_INITIALIZER;

void RulesDumpTxMatchArray(const DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        const Packet *p, const uint64_t tx_id, const uint32_t rule_cnt,
        const uint32_t pkt_prefilter_cnt)
{
    SCJsonBuilder *js =
            CreateEveHeaderWithTxId(p, LOG_DIR_PACKET, "inspectedrules", NULL, tx_id, NULL);
    if (js == NULL)
        return;

    SCJbSetString(js, "app_proto", AppProtoToString(p->flow->alproto));

    SCJbOpenObject(js, "inspectedrules");
    SCJbSetString(js, "inspect_type", "tx");
    SCJbSetUint(js, "rule_group_id", sgh->id);
    SCJbSetUint(js, "rule_cnt", rule_cnt);
    SCJbSetUint(js, "pkt_rule_cnt", pkt_prefilter_cnt);

    SCJbOpenArray(js, "rules");
    for (uint32_t x = 0; x < rule_cnt; x++) {
        SigIntId iid = det_ctx->tx_candidates[x].id;
        const Signature *s = det_ctx->de_ctx->sig_array[iid];
        if (s == NULL)
            continue;
        SCJbAppendUint(js, s->id);
    }
    SCJbClose(js); // close array
    SCJbClose(js); // close inspectedrules object
    SCJbClose(js); // final close

    const char *filename = "packet_inspected_rules.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rule_dump_write_m);
    FILE *fp = fopen(log_path, "a");
    if (fp != NULL) {
        fwrite(SCJbPtr(js), SCJbLen(js), 1, fp);
        fclose(fp);
    }
    SCMutexUnlock(&g_rule_dump_write_m);
    SCJbFree(js);
}

void RulesDumpMatchArray(const DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, const Packet *p)
{
    SCJsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "inspectedrules", NULL, NULL);
    if (js == NULL)
        return;

    if (p->flow) {
        SCJbSetString(js, "app_proto", AppProtoToString(p->flow->alproto));
    }

    SCJbOpenObject(js, "inspectedrules");
    SCJbSetString(js, "inspect_type", "packet");
    SCJbSetUint(js, "rule_group_id", sgh->id);
    SCJbSetUint(js, "rule_cnt", det_ctx->match_array_cnt);

    SCJbOpenArray(js, "rules");
    for (uint32_t x = 0; x < det_ctx->match_array_cnt; x++) {
        const Signature *s = det_ctx->match_array[x];
        if (s == NULL)
            continue;
        SCJbAppendUint(js, s->id);
    }
    SCJbClose(js); // close array
    SCJbClose(js); // close inspectedrules object
    SCJbClose(js); // final close

    const char *filename = "packet_inspected_rules.json";
    const char *log_dir = SCConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rule_dump_write_m);
    FILE *fp = fopen(log_path, "a");
    if (fp != NULL) {
        fwrite(SCJbPtr(js), SCJbLen(js), 1, fp);
        fclose(fp);
    }
    SCMutexUnlock(&g_rule_dump_write_m);
    SCJbFree(js);
}
#endif /* PROFILING */
