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
#ifdef PROFILING
#include "util-print.h"
#include "util-buffer.h"
#include "output-json.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect.h"
#include "suricata.h"
#endif
#include "detect-engine-profile.h"

#ifdef PROFILING
SCMutex g_rule_dump_write_m = SCMUTEX_INITIALIZER;

void RulesDumpTxMatchArray(const DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh,
        const Packet *p, const uint64_t tx_id, const uint32_t rule_cnt,
        const uint32_t pkt_prefilter_cnt)
{
    JsonBuilder *js =
            CreateEveHeaderWithTxId(p, LOG_DIR_PACKET, "inspectedrules", NULL, tx_id, NULL);
    if (js == NULL)
        return;

    jb_set_string(js, "app_proto", AppProtoToString(p->flow->alproto));

    jb_open_object(js, "inspectedrules");
    jb_set_string(js, "inspect_type", "tx");
    jb_set_uint(js, "rule_group_id", sgh->id);
    jb_set_uint(js, "rule_cnt", rule_cnt);
    jb_set_uint(js, "pkt_rule_cnt", pkt_prefilter_cnt);
    jb_set_uint(js, "non_pf_rule_cnt", det_ctx->non_pf_store_cnt);

    jb_open_array(js, "rules");
    for (uint32_t x = 0; x < rule_cnt; x++) {
        SigIntId iid = det_ctx->tx_candidates[x].id;
        const Signature *s = det_ctx->de_ctx->sig_array[iid];
        if (s == NULL)
            continue;
        jb_append_uint(js, s->id);
    }
    jb_close(js); // close array
    jb_close(js); // close inspectedrules object
    jb_close(js); // final close

    const char *filename = "packet_inspected_rules.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rule_dump_write_m);
    FILE *fp = fopen(log_path, "a");
    if (fp != NULL) {
        fwrite(jb_ptr(js), jb_len(js), 1, fp);
        fclose(fp);
    }
    SCMutexUnlock(&g_rule_dump_write_m);
    jb_free(js);
}

void RulesDumpMatchArray(const DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh, const Packet *p)
{
    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "inspectedrules", NULL, NULL);
    if (js == NULL)
        return;

    if (p->flow) {
        jb_set_string(js, "app_proto", AppProtoToString(p->flow->alproto));
    }

    jb_open_object(js, "inspectedrules");
    jb_set_string(js, "inspect_type", "packet");
    jb_set_uint(js, "rule_group_id", sgh->id);
    jb_set_uint(js, "rule_cnt", det_ctx->match_array_cnt);
    jb_set_uint(js, "non_pf_rule_cnt", det_ctx->non_pf_store_cnt);

    jb_open_array(js, "rules");
    for (uint32_t x = 0; x < det_ctx->match_array_cnt; x++) {
        const Signature *s = det_ctx->match_array[x];
        if (s == NULL)
            continue;
        jb_append_uint(js, s->id);

    }
    jb_close(js); // close array
    jb_close(js); // close inspectedrules object
    jb_close(js); // final close

    const char *filename = "packet_inspected_rules.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rule_dump_write_m);
    FILE *fp = fopen(log_path, "a");
    if (fp != NULL) {
        fwrite(jb_ptr(js), jb_len(js), 1, fp);
        fclose(fp);
    }
    SCMutexUnlock(&g_rule_dump_write_m);
    jb_free(js);
}
#endif /* PROFILING */
