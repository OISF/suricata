/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef SURICATA_DETECT_ENGINE_BUFFER_H
#define SURICATA_DETECT_ENGINE_BUFFER_H

// types from detect.h with only forward declarations for bindgen
// could be #ifndef SURICATA_BINDGEN_H #include "detect.h" #endif
typedef struct DetectEngineCtx_ DetectEngineCtx;
typedef struct Signature_ Signature;
typedef struct SigMatch_ SigMatch;

int WARN_UNUSED SCDetectBufferSetActiveList(DetectEngineCtx *de_ctx, Signature *s, const int list);
int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s);
SigMatch *DetectBufferGetFirstSigMatch(const Signature *s, const uint32_t buf_id);
SigMatch *DetectBufferGetLastSigMatch(const Signature *s, const uint32_t buf_id);
int SCDetectSignatureAddTransform(Signature *s, int transform, void *options);

#endif /* SURICATA_DETECT_ENGINE_BUFFER_H */
