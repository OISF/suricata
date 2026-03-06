/* Copyright (C) 2026 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements the windows_pe keyword for detecting Windows PE files in
 * network traffic with optional metadata matching.
 *
 * The windows_pe keyword can be used alone or with option(s):
 *
 *   windows_pe;
 *   windows_pe: arch <arch>
 *               [, size <uint32>][, sections <uint16>]
 *               [, entry_point <uint32>]
 *               [, subsystem <uint16>][, characteristics <uint16>]
 *               [, dll_characteristics <uint16>];
 *
 * Option parsing is performed in Rust (SCDetectWindowsPEParse) following
 * the pattern established by detect-bytemath.c / byte_math.rs.
 */

#include "suricata-common.h"
#include "detect-windows-pe.h"
#include "app-layer-parser.h"
#include "detect-engine-helper.h"
#include "detect-engine-prefilter.h"
#include "util-prefilter.h"
#include "rust.h"

/* Forward declaration for Rust FFI */
extern void SCDetectWindowsPERegister(void);

typedef struct PrefilterWindowsPEData_ {
    uint32_t size;
    SigIntId array[];
} PrefilterWindowsPEData;

static uint16_t g_windows_pe_kw_id = UINT16_MAX;
static int g_windows_pe_files_list_id = -1;

static void PrefilterWindowsPEDataFree(void *ptr)
{
    SCFree(ptr);
}

static bool SignatureHasKeyword(const Signature *s, const uint16_t kw_id)
{
    if (s == NULL || s->init_data == NULL) {
        return false;
    }

    for (int i = 0; i < DETECT_SM_LIST_MAX; i++) {
        for (const SigMatch *sm = s->init_data->smlists[i]; sm != NULL; sm = sm->next) {
            if (sm->type == kw_id) {
                return true;
            }
        }
    }

    for (uint32_t i = 0; i < s->init_data->buffer_index; i++) {
        for (const SigMatch *sm = s->init_data->buffers[i].head; sm != NULL; sm = sm->next) {
            if (sm->type == kw_id) {
                return true;
            }
        }
    }

    return false;
}

static bool WindowsPESupportsPrefilter(const Signature *s)
{
    if (g_windows_pe_kw_id == UINT16_MAX) {
        return false;
    }
    return SignatureHasKeyword(s, g_windows_pe_kw_id);
}

static void WindowsPEPrefilterTx(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *txd, const uint8_t flags)
{
    (void)p;
    (void)idx;

    if (f == NULL || txv == NULL || txd == NULL) {
        return;
    }
    if (!AppLayerParserHasFilesInDir(txd, flags)) {
        return;
    }

    const PrefilterWindowsPEData *ctx = (const PrefilterWindowsPEData *)pectx;
    if (ctx == NULL || ctx->size == 0) {
        return;
    }

    AppLayerGetFileState files = AppLayerParserGetTxFiles(f, txv, flags);
    FileContainer *ffc = files.fc;
    if (ffc == NULL || ffc->head == NULL) {
        return;
    }

    bool add_sids = false;
    for (File *file = ffc->head; file != NULL; file = file->next) {
        if (file->state == FILE_STATE_NONE) {
            continue;
        }

        uint32_t data_len = 0;
        uint64_t offset = 0;
        const uint8_t *data = SCFileGetData(file, &data_len, &offset);

        /* If the stream window no longer starts at file offset 0, be conservative:
         * include candidates and let full matcher decide. */
        if (offset != 0) {
            add_sids = true;
            break;
        }
        if (data == NULL || data_len < 64) {
            continue;
        }
        if (data[0] == 'M' && data[1] == 'Z') {
            /* Also validate PE signature to reduce false prefilter hits
             * from non-PE files that happen to start with "MZ". */
            uint32_t pe_off = (uint32_t)data[60] | ((uint32_t)data[61] << 8) |
                              ((uint32_t)data[62] << 16) | ((uint32_t)data[63] << 24);
            if (pe_off <= 0x10000 && pe_off + 4 <= data_len && data[pe_off] == 'P' &&
                    data[pe_off + 1] == 'E' && data[pe_off + 2] == 0 && data[pe_off + 3] == 0) {
                add_sids = true;
                break;
            }
        }
    }

    if (add_sids) {
        PrefilterAddSids(&det_ctx->pmq, ctx->array, ctx->size);
    }
}

static int WindowsPESetupPrefilter(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (g_windows_pe_kw_id == UINT16_MAX || g_windows_pe_files_list_id < 0) {
        return 0;
    }

    uint32_t count = 0;
    for (uint32_t i = 0; i < sgh->init->sig_cnt; i++) {
        Signature *s = sgh->init->match_array[i];
        if (s == NULL || s->init_data == NULL) {
            continue;
        }
        if (!SignatureHasKeyword(s, g_windows_pe_kw_id)) {
            continue;
        }
        count++;
    }

    if (count == 0) {
        return 0;
    }

    PrefilterWindowsPEData *data =
            SCCalloc(1, sizeof(*data) + (size_t)count * sizeof(data->array[0]));
    if (data == NULL) {
        return -1;
    }
    data->size = count;

    uint32_t pos = 0;
    for (uint32_t i = 0; i < sgh->init->sig_cnt; i++) {
        Signature *s = sgh->init->match_array[i];
        if (s == NULL || s->init_data == NULL) {
            continue;
        }
        if (!SignatureHasKeyword(s, g_windows_pe_kw_id)) {
            continue;
        }
        data->array[pos++] = s->iid;
        s->flags |= SIG_FLAG_PREFILTER;
    }

    if (PrefilterAppendTxEngine(de_ctx, sgh, WindowsPEPrefilterTx, ALPROTO_UNKNOWN, -1, data,
                PrefilterWindowsPEDataFree, "windows_pe") < 0) {
        SCFree(data);
        return -1;
    }
    return 0;
}

void SCDetectWindowsPEEnablePrefilter(uint16_t keyword_id, int files_list_id)
{
    g_windows_pe_kw_id = keyword_id;
    g_windows_pe_files_list_id = files_list_id;

    sigmatch_table[keyword_id].SupportsPrefilter = WindowsPESupportsPrefilter;
    sigmatch_table[keyword_id].SetupPrefilter = WindowsPESetupPrefilter;
}

void DetectWindowsPERegister(void)
{
    SCDetectWindowsPERegister();
}
