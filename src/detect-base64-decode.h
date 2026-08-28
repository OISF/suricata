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
 * Public interface for the "base64_decode" rule keyword.
 *
 * Decodes a slice of the inspection buffer as base64 into
 * det_ctx->base64_decoded. The destination buffer is sized once at
 * ruleset compile time from de_ctx->base64_decode_max_len (the
 * largest `bytes` value any rule in the set asks for). A following
 * "base64_data" keyword then redirects subsequent content matches
 * onto that decoded buffer.
 */

#ifndef SURICATA_DETECT_BASE64_DECODE_H
#define SURICATA_DETECT_BASE64_DECODE_H

/** \brief Register the "base64_decode" keyword with the detect engine. */
void DetectBase64DecodeRegister(void);

/** \brief Perform the decode at match time.
 *
 *  Supports the keyword's bytes/offset/relative options: `offset`
 *  skips leading payload bytes, `relative` makes that offset start
 *  from the previous match, and `bytes` caps the amount decoded.
 *  On success det_ctx->base64_decoded and ->base64_decoded_len are
 *  updated in place.
 *
 *  \retval 1 something was decoded
 *  \retval 0 nothing decoded (empty slice, offset past end, or decode failure) */
int DetectBase64DecodeDoMatch(DetectEngineThreadCtx *, const Signature *,
    const SigMatchData *, const uint8_t *, uint32_t);

#endif /* SURICATA_DETECT_BASE64_DECODE_H */
