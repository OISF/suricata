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

/* ANSI colors used to make the trace readable on a terminal. They are empty
 * strings unless DetectTraceInit() finds an interactive stdout, so the same
 * format strings serve both the colored and the plain output. */
static const char *c_rst = "";
static const char *c_red = "";
static const char *c_grn = "";
static const char *c_blu = "";
static const char *c_mag = "";
static const char *c_cyn = "";
/* the bytes a keyword just matched, and the byte the next keyword starts at */
static const char *c_match = "";
static const char *c_cursor = "";

bool g_detect_trace_enabled = false;
static bool g_detect_trace_color = false;

void DetectTraceInit(void)
{
    g_detect_trace_enabled = (getenv("SURICATA_DETECT_TRACE") != NULL);
    if (!g_detect_trace_enabled)
        return;

    /* Escape sequences only help on a terminal: they are noise in a file and
     * they would swamp a hexdump. NO_COLOR (https://no-color.org/) turns them
     * off even there. */
    const char *no_color = getenv("NO_COLOR");
#ifndef OS_WIN32
    g_detect_trace_color = isatty(fileno(stdout)) && (no_color == NULL || no_color[0] == '\0');
#endif
    if (g_detect_trace_color) {
        c_rst = "\033[0m";
        c_red = "\033[31m";
        c_grn = "\033[32m";
        c_blu = "\033[34m";
        c_mag = "\033[35m";
        c_cyn = "\033[36m";
        /* explicit foreground and background so the markers render the same
         * whatever the terminal's own palette is */
        c_match = "\033[30;102m";
        c_cursor = "\033[30;103m";
    }

    SCLogNotice("detection-engine inspection tracing enabled "
                "(SURICATA_DETECT_TRACE set); output goes to stdout");
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

/** \brief how a byte of the dump is called out, if at all */
enum DetectTraceMark {
    TRACE_MARK_NONE = 0,
    TRACE_MARK_MATCH,
    TRACE_MARK_CURSOR,
};

/** \brief width of the gutter and offset column preceding the hex bytes */
#define TRACE_DUMP_PREFIX 11

/** \brief classify byte \p i of the buffer against the marked region */
static enum DetectTraceMark DetectTraceByteMark(
        uint32_t i, uint32_t hl_start, uint32_t hl_end, uint32_t cursor, bool has_cursor)
{
    if (has_cursor && i == cursor)
        return TRACE_MARK_CURSOR;
    if (i >= hl_start && i < hl_end)
        return TRACE_MARK_MATCH;
    return TRACE_MARK_NONE;
}

static const char *DetectTraceMarkColor(enum DetectTraceMark mark)
{
    switch (mark) {
        case TRACE_MARK_MATCH:
            return c_match;
        case TRACE_MARK_CURSOR:
            return c_cursor;
        case TRACE_MARK_NONE:
            break;
    }
    return "";
}

/**
 * \brief Whether the highlight should run through the separator after byte \p i.
 *
 * It continues only into a neighbour on the same row carrying the same mark, so
 * a span reads as one bar instead of as detached pairs, without the background
 * bleeding past the end of the row.
 */
static bool DetectTraceMarkJoins(uint32_t i, uint32_t rowend, enum DetectTraceMark mark,
        uint32_t hl_start, uint32_t hl_end, uint32_t cursor, bool has_cursor)
{
    if (mark == TRACE_MARK_NONE || i + 1 >= rowend)
        return false;
    return DetectTraceByteMark(i + 1, hl_start, hl_end, cursor, has_cursor) == mark;
}

/** \brief the caret glyph standing in for a color when there is no terminal */
static char DetectTraceMarkGlyph(enum DetectTraceMark mark)
{
    switch (mark) {
        case TRACE_MARK_MATCH:
            return '^';
        case TRACE_MARK_CURSOR:
            return '*';
        case TRACE_MARK_NONE:
            break;
    }
    return ' ';
}

/**
 * \brief Hexdump of \p buf around the current inspection \p cursor.
 *
 * Large payload/stream buffers are windowed so the trace doesn't flood the
 * terminal. Row offsets are absolute within the buffer, so they can be read
 * against the offsets the rest of the trace prints without any arithmetic.
 *
 * \p match_len is the number of bytes the keyword just consumed. Those bytes
 * end at \p cursor rather than starting there, so they are highlighted as the
 * span [cursor - match_len, cursor) and \p cursor itself is marked separately
 * as the point the next keyword starts from.
 */
static void DetectTraceHexdump(
        const uint8_t *buf, uint32_t len, uint32_t cursor, uint32_t match_len)
{
    const uint32_t window = 256; /* bytes of context on each side of the cursor */

    uint32_t start = (cursor > window) ? cursor - window : 0;
    start &= ~0xFU; /* align rows to 16 so the columns stay in fixed positions */
    uint32_t end = (cursor + window < len) ? cursor + window : len;
    if (start >= end) {
        start = 0;
        end = len;
    }

    const bool span = (match_len > 0 && match_len <= cursor);
    const uint32_t hl_start = span ? cursor - match_len : 0;
    const uint32_t hl_end = span ? cursor : 0; /* exclusive */
    const bool has_cursor = (cursor < len);

    printf("TRACE buffer window +%u..+%u of %u (", start, end, len);
    if (span)
        printf("match +%u..+%u, ", hl_start, hl_end);
    printf("cursor +%u%s)", cursor, has_cursor ? "" : " past end");
    if (!g_detect_trace_color)
        printf(" [^ match, * cursor]");
    printf(":\n");

    for (uint32_t u = start; u < end; u += 16) {
        const uint32_t rowend = (u + 16 < end) ? u + 16 : end;

        bool marked = false;
        for (uint32_t i = u; i < rowend; i++) {
            if (DetectTraceByteMark(i, hl_start, hl_end, cursor, has_cursor) != TRACE_MARK_NONE) {
                marked = true;
                break;
            }
        }

        printf("%c%08X  ", marked ? '>' : ' ', u);

        uint32_t ch;
        for (ch = 0; u + ch < rowend; ch++) {
            const enum DetectTraceMark mark =
                    DetectTraceByteMark(u + ch, hl_start, hl_end, cursor, has_cursor);
            const bool joins = DetectTraceMarkJoins(
                    u + ch, rowend, mark, hl_start, hl_end, cursor, has_cursor);
            const char *esc = (mark == TRACE_MARK_NONE) ? "" : DetectTraceMarkColor(mark);

            printf("%s%02X%s ", esc, buf[u + ch], (mark != TRACE_MARK_NONE && !joins) ? c_rst : "");
            if (ch == 7)
                putchar(' ');
            if (joins)
                printf("%s", c_rst);
        }
        /* pad a short final row so the ascii column stays where it belongs */
        for (uint32_t pad = ch; pad < 16; pad++) {
            printf("   ");
            if (pad == 7)
                putchar(' ');
        }
        printf("  ");

        for (ch = 0; u + ch < rowend; ch++) {
            const uint8_t c = buf[u + ch];
            const char pc = isprint(c) ? (char)c : '.';
            const enum DetectTraceMark mark =
                    DetectTraceByteMark(u + ch, hl_start, hl_end, cursor, has_cursor);
            const bool joins = DetectTraceMarkJoins(
                    u + ch, rowend, mark, hl_start, hl_end, cursor, has_cursor);
            const char *esc = (mark == TRACE_MARK_NONE) ? "" : DetectTraceMarkColor(mark);

            printf("%s%c%s", esc, pc, (mark != TRACE_MARK_NONE && !joins) ? c_rst : "");
            if (ch == 7)
                putchar(' ');
            if (joins)
                printf("%s", c_rst);
        }
        putchar('\n');

        /* with no color to carry it, the marked bytes get a row of their own */
        if (!g_detect_trace_color && marked) {
            for (int i = 0; i < TRACE_DUMP_PREFIX; i++)
                putchar(' ');
            for (ch = 0; u + ch < rowend; ch++) {
                const char glyph = DetectTraceMarkGlyph(
                        DetectTraceByteMark(u + ch, hl_start, hl_end, cursor, has_cursor));
                printf("%c%c ", glyph, glyph);
                if (ch == 7)
                    putchar(' ');
            }
            putchar('\n');
        }
    }
}

/**
 * \brief Number of bytes the keyword consumed, ending at the post-detect offset.
 *
 * A positive, non-negated content match is the only case that moves
 * det_ctx->buffer_offset to the end of the bytes it matched (match_offset in
 * DetectEngineContentInspectionInternal()); every other keyword and every
 * no-match leaves the offset as a bare cursor with no span to show.
 */
static uint32_t DetectTraceMatchLen(const SigMatchData *smd, int result)
{
    if (result != 1 || smd->type != DETECT_CONTENT)
        return 0;

    const DetectContentData *cd = (const DetectContentData *)smd->ctx;
    if (cd->flags & DETECT_CONTENT_NEGATED)
        return 0;
    return cd->content_len;
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

            snprintf(out, outlen, "content:%s\"%s%s%s\"%s (len %u)",
                    (cd->flags & DETECT_CONTENT_NEGATED) ? "!" : "", c_grn, content, c_rst, mods,
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
            snprintf(out, outlen, "pcre:%s\"%s%s%s\"%s",
                    (pe->flags & DETECT_PCRE_NEGATE) ? "!" : "", c_grn,
                    pe->parse_regex.regexstr ? pe->parse_regex.regexstr : "(unknown)", c_rst, mods);
            break;
        }
        case DETECT_ISDATAAT: {
            const DetectIsdataatData *id = (const DetectIsdataatData *)smd->ctx;
            snprintf(out, outlen, "isdataat:%s%s%u%s%s", (id->flags & ISDATAAT_NEGATED) ? "!" : "",
                    c_grn, id->dataat, c_rst, (id->flags & ISDATAAT_RELATIVE) ? " relative" : "");
            break;
        }
        case DETECT_BYTETEST: {
            const DetectBytetestData *btd = (const DetectBytetestData *)smd->ctx;
            snprintf(out, outlen,
                    "byte_test:%sbytes %u, op %u, value %" PRIu64 ", offset %d, bitmask 0x%x%s",
                    c_grn, btd->nbytes, btd->op, btd->value, btd->offset, btd->bitmask, c_rst);
            break;
        }
        case DETECT_BYTEJUMP: {
            const DetectBytejumpData *bjd = (const DetectBytejumpData *)smd->ctx;
            snprintf(out, outlen, "byte_jump:%sbytes %u, offset %d, post_offset %d%s", c_grn,
                    bjd->nbytes, bjd->offset, bjd->post_offset, c_rst);
            break;
        }
        case DETECT_BASE64_DECODE: {
            const DetectBase64Decode *bd = (const DetectBase64Decode *)smd->ctx;
            snprintf(out, outlen, "base64_decode:%sbytes %u, offset %u, relative %s%s", c_grn,
                    bd->bytes, bd->offset, bd->relative ? "true" : "false", c_rst);
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
    printf(" Mode: %s%s%s", c_red, DetectTraceModeName(inspection_mode), c_rst);
    if (s->alproto != ALPROTO_UNKNOWN)
        printf("  AppProto: %s%s%s", c_red, AppProtoToString(s->alproto), c_rst);
    printf("  Buffer: %s%s%s", c_mag, bufname ? bufname : "(null)", c_rst);
    printf("  Match Type: %s%s%s", c_blu, sigmatch_table[smd->type].name, c_rst);
    printf("  Recursion: %s%u/%u%s\n", c_grn, recursion, recursion_limit, c_rst);
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
        printf("TRACE (%u) -> %sMATCH!%s <-  (%s)\n", s->id, c_cyn, c_rst,
                sigmatch_table[smd->type].name);
    } else {
        printf("TRACE (%u) -> %sNO MATCH!%s <-%s  (%s)\n", s->id, c_red, c_rst,
                (result == -1) ? " [discontinue]" : "", sigmatch_table[smd->type].name);
    }
    printf("TRACE (%u) post-detect offset: %s%u%s\n", s->id, c_grn, offset, c_rst);
    if (buffer != NULL)
        DetectTraceHexdump(buffer, buffer_len, offset, DetectTraceMatchLen(smd, result));
    fflush(stdout);
    funlockfile(stdout);
}

#endif /* DETECT_TRACE */
