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
 * See detect-engine-inspect-trace.h for an overview.
 */

#include "suricata-common.h"
#include "detect-engine-inspect-trace.h"

#ifdef DETECT_TRACE

#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-urilen.h"
#include "detect-base64-decode.h"

#include "app-layer-protos.h"
#include "util-print.h"

/* ANSI colors used to make the trace readable on a terminal. */
#define C_RST "\033[0m"
#define C_RED "\033[31m"
#define C_GRN "\033[32m"
#define C_BLU "\033[34m"
#define C_MAG "\033[35m"
#define C_CYN "\033[36m"

bool g_detect_trace_enabled = false;

void DetectTraceInit(void)
{
    g_detect_trace_enabled = (getenv("SURICATA_DETECT_TRACE") != NULL);
    if (g_detect_trace_enabled) {
        SCLogNotice("detection-engine inspection tracing enabled "
                    "(SURICATA_DETECT_TRACE set); output goes to stdout");
    }
}

static const char *DetectTraceModeName(enum DetectContentInspectionType mode)
{
    switch (mode) {
        case DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD:
            return "payload";
        case DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER:
            return "header";
        case DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM:
            return "stream";
        case DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME:
            return "frame";
        case DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE:
            return "state";
    }
    return "unknown";
}

/**
 * \brief Hexdump of \p buf around the current inspection \p offset.
 *
 * Large payload/stream buffers are windowed so the trace doesn't flood the
 * terminal; the actual formatting reuses the standard PrintRawDataFp() dumper.
 * The window is anchored with a header line since PrintRawDataFp() numbers its
 * rows from the start of the slice it is given.
 */
static void DetectTraceHexdump(const uint8_t *buf, uint32_t len, uint32_t offset)
{
    const uint32_t window = 256; /* bytes of context on each side of offset */

    uint32_t start = (offset > window) ? offset - window : 0;
    start &= ~0xFU; /* align to 16 so PrintRawDataFp rows line up */
    uint32_t end = (offset + window < len) ? offset + window : len;
    if (start >= end) {
        start = 0;
        end = len;
    }

    printf("TRACE buffer window +%u..+%u of %u (detect offset +%u):\n", start, end, len, offset);
    PrintRawDataFp(stdout, buf + start, end - start);
}

/** \brief append " name:value" for a set flag, into a fixed buffer */
static void DetectTraceAppend(char *dst, size_t dstlen, const char *text)
{
    strlcat(dst, text, dstlen);
}

/** \brief render the keyword-specific parameters into \p out */
static void DetectTraceKeywordDetail(const SigMatchData *smd, char *out, size_t outlen)
{
    out[0] = '\0';

    switch (smd->type) {
        case DETECT_CONTENT: {
            const DetectContentData *cd = (const DetectContentData *)smd->ctx;
            char content[1024] = "";
            uint32_t o = 0;
            PrintRawUriBuf(content, &o, sizeof(content), cd->content, cd->content_len);

            char mods[256] = "";
            char tmp[64];
            if (cd->flags & DETECT_CONTENT_OFFSET) {
                snprintf(tmp, sizeof(tmp), " offset:%u", cd->offset);
                DetectTraceAppend(mods, sizeof(mods), tmp);
            }
            if (cd->flags & DETECT_CONTENT_DEPTH) {
                snprintf(tmp, sizeof(tmp), " depth:%u", cd->depth);
                DetectTraceAppend(mods, sizeof(mods), tmp);
            }
            if (cd->flags & DETECT_CONTENT_DISTANCE) {
                snprintf(tmp, sizeof(tmp), " distance:%d", cd->distance);
                DetectTraceAppend(mods, sizeof(mods), tmp);
            }
            if (cd->flags & DETECT_CONTENT_WITHIN) {
                snprintf(tmp, sizeof(tmp), " within:%d", cd->within);
                DetectTraceAppend(mods, sizeof(mods), tmp);
            }
            if (cd->flags & DETECT_CONTENT_STARTS_WITH)
                DetectTraceAppend(mods, sizeof(mods), " startswith");
            if (cd->flags & DETECT_CONTENT_ENDS_WITH)
                DetectTraceAppend(mods, sizeof(mods), " endswith");
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN)
                DetectTraceAppend(mods, sizeof(mods), " fast_pattern");
            if (cd->flags & DETECT_CONTENT_RAWBYTES)
                DetectTraceAppend(mods, sizeof(mods), " rawbytes");

            snprintf(out, outlen, "content:%s\"" C_GRN "%s" C_RST "\"%s (len %u)",
                    (cd->flags & DETECT_CONTENT_NEGATED) ? "!" : "", content, mods,
                    cd->content_len);
            break;
        }
        case DETECT_PCRE: {
            const DetectPcreData *pe = (const DetectPcreData *)smd->ctx;
            char mods[64] = "";
            if (pe->flags & DETECT_PCRE_RELATIVE)
                DetectTraceAppend(mods, sizeof(mods), " relative");
            if (pe->flags & DETECT_PCRE_CASELESS)
                DetectTraceAppend(mods, sizeof(mods), " nocase");
            if (pe->flags & DETECT_PCRE_RAWBYTES)
                DetectTraceAppend(mods, sizeof(mods), " rawbytes");
            snprintf(out, outlen, "pcre:%s\"" C_GRN "%s" C_RST "\"%s",
                    (pe->flags & DETECT_PCRE_NEGATE) ? "!" : "",
                    pe->parse_regex.regexstr ? pe->parse_regex.regexstr : "(unknown)", mods);
            break;
        }
        case DETECT_ISDATAAT: {
            const DetectIsdataatData *id = (const DetectIsdataatData *)smd->ctx;
            snprintf(out, outlen, "isdataat:%s" C_GRN "%u" C_RST "%s",
                    (id->flags & ISDATAAT_NEGATED) ? "!" : "", id->dataat,
                    (id->flags & ISDATAAT_RELATIVE) ? " relative" : "");
            break;
        }
        case DETECT_BYTETEST: {
            const DetectBytetestData *btd = (const DetectBytetestData *)smd->ctx;
            snprintf(out, outlen,
                    "byte_test:" C_GRN "bytes %u, op %u, value %" PRIu64
                    ", offset %d, bitmask 0x%x" C_RST,
                    btd->nbytes, btd->op, btd->value, btd->offset, btd->bitmask);
            break;
        }
        case DETECT_BYTEJUMP: {
            const DetectBytejumpData *bjd = (const DetectBytejumpData *)smd->ctx;
            snprintf(out, outlen, "byte_jump:" C_GRN "bytes %u, offset %d, post_offset %d" C_RST,
                    bjd->nbytes, bjd->offset, bjd->post_offset);
            break;
        }
        case DETECT_BASE64_DECODE: {
            const DetectBase64Decode *bd = (const DetectBase64Decode *)smd->ctx;
            snprintf(out, outlen, "base64_decode:" C_GRN "bytes %u, offset %u, relative %s" C_RST,
                    bd->bytes, bd->offset, bd->relative ? "true" : "false");
            break;
        }
        default:
            /* no dedicated formatter; the keyword name is shown in the header */
            break;
    }
}

void DetectTraceKeyword(const DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchData *smd, const Packet *p, enum DetectContentInspectionType inspection_mode,
        uint32_t recursion, uint32_t recursion_limit)
{
    char detail[1400];
    DetectTraceKeywordDetail(smd, detail, sizeof(detail));

    /* The current buffer/list id is only tracked on det_ctx when profiling is
     * compiled in; without it we simply omit the buffer name. */
    const char *bufname = NULL;
#ifdef PROFILING
    if (det_ctx->de_ctx != NULL) {
        bufname = DetectEngineBufferTypeGetNameById(det_ctx->de_ctx, det_ctx->keyword_perf_list);
    }
#endif

    flockfile(stdout);
    for (int i = 0; i < 78; i++)
        putchar('-');
    printf("\nTRACE (%u) MSG: %s\n", s->id, s->msg ? s->msg : "");
    printf("TRACE (%u)", s->id);
    if (p != NULL)
        printf(" Packet: %" PRIu64, PcapPacketCntGet(p));
    printf(" Mode: " C_RED "%s" C_RST, DetectTraceModeName(inspection_mode));
    if (s->alproto != ALPROTO_UNKNOWN)
        printf("  AppProto: " C_RED "%s" C_RST, AppProtoToString(s->alproto));
    printf("  Buffer: " C_MAG "%s" C_RST, bufname ? bufname : "(null)");
    printf("  Match Type: " C_BLU "%s" C_RST, sigmatch_table[smd->type].name);
    printf("  Recursion: " C_GRN "%u/%u" C_RST "\n", recursion, recursion_limit);
    if (detail[0] != '\0')
        printf("TRACE (%u) Inspecting %s\n", s->id, detail);
    fflush(stdout);
    funlockfile(stdout);
}

void DetectTraceResult(const Signature *s, const SigMatchData *smd, const uint8_t *buffer,
        uint32_t buffer_len, uint32_t offset, int result)
{
    flockfile(stdout);
    if (result == 1) {
        printf("TRACE (%u) -> " C_CYN "MATCH!" C_RST " <-  (%s)\n", s->id,
                sigmatch_table[smd->type].name);
    } else {
        printf("TRACE (%u) -> " C_RED "NO MATCH!" C_RST " <-%s  (%s)\n", s->id,
                (result == -1) ? " [discontinue]" : "", sigmatch_table[smd->type].name);
    }
    printf("TRACE (%u) post-detect offset: " C_GRN "%u" C_RST "\n", s->id, offset);
    if (buffer != NULL)
        DetectTraceHexdump(buffer, buffer_len, offset);
    fflush(stdout);
    funlockfile(stdout);
}

#endif /* DETECT_TRACE */
