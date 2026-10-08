/* Copyright (C) 2015-2022 Open Information Security Foundation
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
 * `base64_decode` rule keyword: base64-decodes part of the current
 * buffer so `base64_data` can match on the result.
 */

#ifndef SURICATA_DETECT_BASE64_DECODE_H
#define SURICATA_DETECT_BASE64_DECODE_H

/** \brief Register the `base64_decode` keyword in sigmatch_table. */
void DetectBase64DecodeRegister(void);

/** \brief Decode part of \p payload into det_ctx->base64_decoded.
 *  Called by the content inspection engine.
 *  \retval 1 something was decoded, 0 otherwise */
int DetectBase64DecodeDoMatch(DetectEngineThreadCtx *, const Signature *,
    const SigMatchData *, const uint8_t *, uint32_t);

#endif /* SURICATA_DETECT_BASE64_DECODE_H */
