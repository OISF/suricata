/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 */

#ifndef __DETECT_ENGINE_CONTENT_INSPECTION_H__
#define __DETECT_ENGINE_CONTENT_INSPECTION_H__

/** indication to content engine what type of data
 *  we're inspecting
 */
enum {
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD = 0,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE,
};

int DetectEngineContentInspection(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                                  const Signature *s, const SigMatchData *smd,
                                  Flow *f,
                                  uint8_t *buffer, uint32_t buffer_len,
                                  uint32_t stream_start_offset,
                                  uint8_t inspection_mode, void *data);

void DetectEngineContentInspectionRegisterTests(void);

#endif /* __DETECT_ENGINE_CONTENT_INSPECTION_H__ */
