/* Copyright (C) 2025-2026 Open Information Security Foundation
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
typedef struct DetectEngineThreadCtx_ DetectEngineThreadCtx;
typedef struct Signature_ Signature;
typedef struct SigMatch_ SigMatch;

int WARN_UNUSED SCDetectBufferSetActiveList(DetectEngineCtx *de_ctx, Signature *s, const int list);
int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s);
SigMatch *DetectBufferGetFirstSigMatch(const Signature *s, const uint32_t buf_id);
SigMatch *DetectBufferGetLastSigMatch(const Signature *s, const uint32_t buf_id);
int SCDetectSignatureAddTransform(Signature *s, int transform, void *options);

// Declared here for bindgen
// But defined in detect-engine.c to access g_master_de_ctx
int SCDetectRegisterThreadCtxGlobalFuncs(
        const char *name, void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *));
void *SCDetectThreadCtxGetGlobalKeywordThreadCtx(DetectEngineThreadCtx *det_ctx, int id);

/** \brief Flag the signature as carrying a transform whose key comes from a
 *  runtime variable; this disqualifies the signature from prefilter/MPM. */
void SCSignatureSetVarTransform(Signature *s);

/**
 * \brief Resolve a byte variable (byte_extract or byte_math) by name for use
 *        as transform input.
 *
 * Returns the runtime slot (local_id) for the named variable. For a
 * byte_extract variable, nbytes is the natural key width (the number of bytes
 * the keyword reads); a byte_math result is a computed value with no inherent
 * width, so nbytes is set to 0 and the caller must supply an explicit width.
 *
 * \retval true  variable found; local_id set, nbytes is the natural width or 0
 * \retval false no such byte variable
 */
bool SCDetectByteVarResolve(
        const Signature *s, const char *name, uint8_t *local_id, uint8_t *nbytes);

/** \brief Read a byte_* variable's runtime value from the thread context. */
uint64_t SCDetectEngineThreadCtxGetByteVar(const DetectEngineThreadCtx *det_ctx, uint8_t id);

#endif /* SURICATA_DETECT_ENGINE_BUFFER_H */
