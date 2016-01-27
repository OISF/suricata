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

/** \warning make sure to add new entries to the proper position
 *           wrt flow lock status
 */
enum {
    /* called with flow unlocked */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD = 0,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STREAM,

    /* called with flow locked */
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_DCE,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_URI,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HRL,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HRUD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HHD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HRHD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HCBD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HSBD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HCD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HMD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HSCD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HSMD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HUAD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HHHD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_HRHHD,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_DNSQUERY,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_FD_SMTP,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_BASE64,
    DETECT_ENGINE_CONTENT_INSPECTION_MODE_TEMPLATE_BUFFER,
};

int DetectEngineContentInspection(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                                  Signature *s, SigMatch *sm,
                                  Flow *f,
                                  uint8_t *buffer, uint32_t buffer_len,
                                  uint32_t stream_start_offset,
                                  uint8_t inspection_mode, void *data);

#endif /* __DETECT_ENGINE_CONTENT_INSPECTION_H__ */
