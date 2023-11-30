/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_ENGINE_CONTENT_INSPECTION_H
#define SURICATA_DETECT_ENGINE_CONTENT_INSPECTION_H

/** indication to content engine what type of data
 *  we're inspecting
 */
enum DetectContentInspectionType {
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD = 0, /* enables 'replace' logic */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER,      /* indicates a header is being inspected */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM,      /* enables "stream" inspection logic */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME,       /* enables "frame" inspection logic */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, /* enables "state" - used for buffers coming from
                                                    the app-layer state. */
};

#define DETECT_CI_FLAGS_START                                                                      \
    BIT_U8(0) /**< indication that current buffer is the start of the data */
#define DETECT_CI_FLAGS_END     BIT_U8(1)   /**< indication that current buffer
                                             *   is the end of the data */
#define DETECT_CI_FLAGS_DCE_LE  BIT_U8(2)   /**< DCERPC record in little endian */
#define DETECT_CI_FLAGS_DCE_BE  BIT_U8(3)   /**< DCERPC record in big endian */

/** buffer is a single, non-streaming, buffer. Data sent to the content
 *  inspection function contains both start and end of the data. */
#define DETECT_CI_FLAGS_SINGLE  (DETECT_CI_FLAGS_START|DETECT_CI_FLAGS_END)

/* implicit "public" just returns true match, false no match */
bool DetectEngineContentInspection(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd, Packet *p, Flow *f, const uint8_t *buffer,
        const uint32_t buffer_len, const uint32_t stream_start_offset, const uint8_t flags,
        const enum DetectContentInspectionType inspection_mode);

/** \brief content inspect entry for inspection buffers
 *  \param de_ctx detection engine
 *  \param det_ctx detect engine thread ctx
 *  \param s signature being inspected
 *  \param smd array of content inspection matches
 *  \param p packet
 *  \param f flow
 *  \param b inspection buffer to inspect
 *  \param inspection_mode inspection mode to use
 *  \retval bool true if smd matched the buffer b, false otherwise */
bool DetectEngineContentInspectionBuffer(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd, Packet *p, Flow *f, const InspectionBuffer *b,
        const enum DetectContentInspectionType inspection_mode);

/** \brief tells if we should match on absent buffer, because
 *  all smd entries are negated
 *  \param smd array of content inspection matches
 *  \retval bool true to match on absent buffer, false otherwise */
bool DetectContentInspectionMatchOnAbsentBuffer(const SigMatchData *smd);

void DetectEngineContentInspectionRegisterTests(void);

#endif /* SURICATA_DETECT_ENGINE_CONTENT_INSPECTION_H */
