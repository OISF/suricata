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
 * All PE metadata fields are options of the single windows_pe keyword:
 *
 *   windows_pe: arch: <arch>
 *               [, size: <uint32>][, sections: <uint16>]
 *               [, entry_point: <uint32>]
 *               [, subsystem: <uint16>][, characteristics: <uint16>]
 *               [, dll_characteristics: <uint16>];
 *
 * Option parsing is performed in Rust (SCDetectWindowsPEParse) following
 * the pattern established by detect-bytemath.c / byte_math.rs.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-helper.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"
#include "detect-windows-pe.h"
#include "util-debug.h"
#include "util-file.h"
#include "util-streaming-buffer.h"
#include "rust.h"

/* Forward declarations for Rust FFI */
extern int SCDetectWindowsPEFileMatch(const void *file_ptr, const uint8_t *data, uint32_t data_len,
        const DetectWindowsPEData *ctx);

/* Keyword ID (dynamically assigned) */
static uint16_t g_windows_pe_kw_id = 0;

/* File match list ID */
static int g_file_match_list_id = 0;

/* Helper: get file data from a File object.
 * Returns the data pointer and length if data starts at offset 0.
 * Returns NULL if no data is available or data doesn't start at offset 0. */
static const uint8_t *GetFileData(const File *file, uint32_t *data_len)
{
    if (file == NULL || file->sb == NULL) {
        *data_len = 0;
        return NULL;
    }

    const uint8_t *data = NULL;
    uint32_t len = 0;
    uint64_t offset = 0;

    StreamingBufferGetData(file->sb, &data, &len, &offset);
    if (offset != 0 || data == NULL || len < 64) {
        *data_len = 0;
        return NULL;
    }

    *data_len = len;
    return data;
}

static int DetectWindowsPEFileMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        File *file, const Signature *s, const SigMatchCtx *m)
{
    const DetectWindowsPEData *ctx = (const DetectWindowsPEData *)m;

    /* Get file data for PE metadata extraction */
    uint32_t data_len = 0;
    const uint8_t *data = GetFileData(file, &data_len);
    if (data == NULL) {
        return 0;
    }

    /* Delegate to single Rust function that handles caching and matching */
    return SCDetectWindowsPEFileMatch((const void *)file, data, data_len, ctx);
}

static int DetectWindowsPESetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectWindowsPEData *data = SCDetectWindowsPEParse(str);
    if (data == NULL) {
        SCLogError("invalid windows_pe keyword options: %s", str ? str : "(null)");
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, g_windows_pe_kw_id, (SigMatchCtx *)data, g_file_match_list_id) == NULL) {
        SCDetectWindowsPEFree(data);
        return -1;
    }

    s->file_flags |= (FILE_SIG_NEED_FILE | FILE_SIG_NEED_FILECONTENT);
    return 0;
}

static void DetectWindowsPEFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectWindowsPEFree(ptr);
}

void DetectWindowsPERegister(void)
{
    /* Register the "files" buffer for file-level matching */
    g_file_match_list_id = DetectBufferTypeRegister("files");

    /* --- windows_pe keyword --- */
    int kw_id = SCDetectHelperNewKeywordId();
    if (kw_id < 0) {
        FatalError("failed to register windows_pe keyword");
    }
    g_windows_pe_kw_id = (uint16_t)kw_id;
    sigmatch_table[g_windows_pe_kw_id].name = "windows_pe";
    sigmatch_table[g_windows_pe_kw_id].desc = "match Windows PE file format and metadata "
                                              "(architecture, size, sections, entry_point, "
                                              "subsystem, characteristics, dll_characteristics)";
    sigmatch_table[g_windows_pe_kw_id].url = "/rules/file-keywords.html#windows_pe";
    sigmatch_table[g_windows_pe_kw_id].FileMatch = DetectWindowsPEFileMatch;
    sigmatch_table[g_windows_pe_kw_id].Setup = DetectWindowsPESetup;
    sigmatch_table[g_windows_pe_kw_id].Free = DetectWindowsPEFree;
    sigmatch_table[g_windows_pe_kw_id].flags = SIGMATCH_OPTIONAL_OPT;

    SCLogDebug("windows_pe keyword registered");
}
