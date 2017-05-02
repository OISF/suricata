/* Copyright (C) 2016 Open Information Security Foundation
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
#include "suricata.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "output-json.h"
#include "util-buffer.h"
#include "util-print.h"
#include "detect-engine-profile.h"

#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
#if 0
static void DumpFp(const SigMatch *sm, char *pat_orig, uint32_t pat_orig_sz, char *pat_chop, uint32_t pat_chop_sz)
{
    int fast_pattern_chop_set = 0;
    const DetectContentData *cd = (DetectContentData *)sm->ctx;

    if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
            fast_pattern_chop_set = 1;
        }
    }

    uint32_t off = 0;
    PrintRawUriBuf(pat_orig, &off, pat_orig_sz, cd->content, cd->content_len);

    if (fast_pattern_chop_set) {
        off = 0;
        PrintRawUriBuf(pat_chop, &off, pat_chop_sz, cd->content + cd->fp_chop_offset, cd->fp_chop_len);
    }
}
#endif

SCMutex g_rule_dump_write_m = SCMUTEX_INITIALIZER;
void RulesDumpMatchArray(const DetectEngineThreadCtx *det_ctx, const Packet *p)
{
    json_t *js = CreateJSONHeader(p, 0, "inspectedrules");
    if (js == NULL)
        return;
    json_t *ir = json_object();
    if (ir == NULL)
        return;

    json_object_set_new(ir, "rule_group_id", json_integer(det_ctx->sgh->id));
    json_object_set_new(ir, "rule_cnt", json_integer(det_ctx->match_array_cnt));

    json_t *js_array = json_array();
    uint32_t x;
    for (x = 0; x < det_ctx->match_array_cnt; x++)
    {
        const Signature *s = det_ctx->match_array[x];
        if (s == NULL)
            continue;

        json_t *js_sig = json_object();
        if (unlikely(js == NULL))
            continue;
        json_object_set_new(js_sig, "sig_id", json_integer(s->id));
#if 0
        json_object_set_new(js_sig, "mpm", (s->mpm_sm != NULL) ? json_true() : json_false());

        if (s->mpm_sm != NULL) {
            char orig[256] = "";
            char chop[256] = "";

            DumpFp(s->mpm_sm, orig, sizeof(orig), chop, sizeof(chop));

            json_object_set_new(js_sig, "mpm_buffer", json_string(DetectListToHumanString(SigMatchListSMBelongsTo(s, s->mpm_sm))));
            json_object_set_new(js_sig, "mpm_pattern", json_string(orig));

            if (strlen(chop) > 0) {
                json_object_set_new(js_sig, "mpm_pattern_chop", json_string(chop));
            }
        }
#endif
        json_array_append_new(js_array, js_sig);
    }

    json_object_set_new(ir, "rules", js_array);
    json_object_set_new(js, "inspectedrules", ir);

    const char *filename = "packet_inspected_rules.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    MemBuffer *mbuf = NULL;
    mbuf = MemBufferCreateNew(4096);
    BUG_ON(mbuf == NULL);

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = &mbuf,
        .expand_by = 4096,
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);
    if (r != 0) {
        SCLogWarning(SC_ERR_SOCKET, "unable to serialize JSON object");
    } else {
        MemBufferWriteString(mbuf, "\n");
        SCMutexLock(&g_rule_dump_write_m);
        FILE *fp = fopen(log_path, "a");
        if (fp != NULL) {
            MemBufferPrintToFPAsString(mbuf, fp);
            fclose(fp);
            SCMutexUnlock(&g_rule_dump_write_m);
        }
    }

    MemBufferFree(mbuf);
    json_object_clear(js);
    json_decref(js);
}
#endif /* HAVE_LIBJANSSON */
#endif /* PROFILING */
