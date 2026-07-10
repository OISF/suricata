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
 * Optional, human-readable tracing of the content-inspection engine. Prints, per
 * inspected keyword, the rule being evaluated, the keyword parameters and a
 * colored hexdump of the buffer around the current inspection offset, followed
 * by the match/no-match outcome.
 *
 * The whole facility is compiled in only when configured with
 * --enable-detect-trace (which defines DETECT_TRACE). Even then it stays silent
 * unless enabled at runtime via the SURICATA_DETECT_TRACE environment variable,
 * so a trace-enabled build pays nothing more than a single predictable branch
 * per keyword when tracing is off.
 */

#ifndef SURICATA_DETECT_ENGINE_INSPECT_TRACE_H
#define SURICATA_DETECT_ENGINE_INSPECT_TRACE_H

#include "detect.h"
#include "detect-engine-content-inspection.h"

#ifdef DETECT_TRACE

/** \brief runtime toggle; set once from the environment by DetectTraceInit() */
extern bool g_detect_trace_enabled;

/** \brief read the SURICATA_DETECT_TRACE environment variable once at startup */
void DetectTraceInit(void);

/** \internal implementation of DETECT_TRACE_KEYWORD() */
void DetectTraceKeyword(const DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchData *smd, const Packet *p, enum DetectContentInspectionType inspection_mode,
        uint32_t recursion, uint32_t recursion_limit);

/** \internal implementation of DETECT_TRACE_RESULT() */
void DetectTraceResult(const Signature *s, const SigMatchData *smd, const uint8_t *buffer,
        uint32_t buffer_len, uint32_t offset, int result);

/**
 * \brief Trace the keyword about to be inspected (rule, parameters, buffer).
 */
#define DETECT_TRACE_KEYWORD(det_ctx, s, smd, p, mode, rec, lim)                                   \
    do {                                                                                           \
        if (unlikely(g_detect_trace_enabled))                                                      \
            DetectTraceKeyword((det_ctx), (s), (smd), (p), (mode), (rec), (lim));                  \
    } while (0)

/**
 * \brief Trace the outcome of the current keyword. \p result is 1 for a match,
 *        0 for no match and -1 for no match with "discontinue".
 */
#define DETECT_TRACE_RESULT(s, smd, buffer, buffer_len, offset, result)                            \
    do {                                                                                           \
        if (unlikely(g_detect_trace_enabled))                                                      \
            DetectTraceResult((s), (smd), (buffer), (buffer_len), (offset), (result));             \
    } while (0)

#else /* !DETECT_TRACE */

static inline void DetectTraceInit(void)
{
}
#define DETECT_TRACE_KEYWORD(det_ctx, s, smd, p, mode, rec, lim)                                   \
    do {                                                                                           \
    } while (0)
#define DETECT_TRACE_RESULT(s, smd, buffer, buffer_len, offset, result)                            \
    do {                                                                                           \
    } while (0)

#endif /* DETECT_TRACE */

#endif /* SURICATA_DETECT_ENGINE_INSPECT_TRACE_H */
