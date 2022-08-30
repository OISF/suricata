/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __DETECT_ENGINE_CONTENT_INSPECTION_H__
#define __DETECT_ENGINE_CONTENT_INSPECTION_H__

/** indication to content engine what type of data
 *  we're inspecting
 */
enum {
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD = 0, /* enables 'replace' logic */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE,
};

#define DETECT_CI_FLAGS_START   BIT_U8(0)   /**< unused, reserved for future use */
#define DETECT_CI_FLAGS_END     BIT_U8(1)   /**< indication that current buffer
                                             *   is the end of the data */
#define DETECT_CI_FLAGS_DCE_LE  BIT_U8(2)   /**< DCERPC record in little endian */
#define DETECT_CI_FLAGS_DCE_BE  BIT_U8(3)   /**< DCERPC record in big endian */

/** buffer is a single, non-streaming, buffer. Data sent to the content
 *  inspection function contains both start and end of the data. */
#define DETECT_CI_FLAGS_SINGLE  (DETECT_CI_FLAGS_START|DETECT_CI_FLAGS_END)

uint8_t DetectEngineContentInspection(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd, Packet *p, Flow *f, const uint8_t *buffer,
        uint32_t buffer_len, uint32_t stream_start_offset, uint8_t flags, uint8_t inspection_mode);

void DetectEngineContentInspectionRegisterTests(void);

#endif /* __DETECT_ENGINE_CONTENT_INSPECTION_H__ */
