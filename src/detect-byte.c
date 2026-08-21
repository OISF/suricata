/* Copyright (C) 2020-2026 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

#include "suricata-common.h"
#include "rust.h"
#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-bytemath.h"
#include "detect-engine-buffer.h"

/**
 * \brief Used to retrieve args from BM.
 *
 * \param arg The name of the variable being sought
 * \param s The signature to check for the variable
 * \param sm_list The caller's matching buffer
 * \param index When found, the value of the slot within the byte vars
 *
 * \retval true A match for the variable was found.
 * \retval false
 */
bool DetectByteRetrieveSMVar(
        const char *arg, const Signature *s, int sm_list, DetectByteIndexType *index)
{
    SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(arg, sm_list, s);
    if (bed_sm != NULL) {
        *index = ((SCDetectByteExtractData *)bed_sm->ctx)->local_id;
        return true;
    }

    SigMatch *bmd_sm = DetectByteMathRetrieveSMVar(arg, sm_list, s);
    if (bmd_sm != NULL) {
        *index = ((DetectByteMathData *)bmd_sm->ctx)->local_id;
        return true;
    }
    return false;
}

bool SCDetectByteVarResolve(
        const Signature *s, const char *name, uint8_t *local_id, uint8_t *nbytes)
{
    /* byte_extract carries a natural key width (the number of bytes it reads),
     * so resolve it directly to get both the runtime slot and that width. */
    SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(name, s->init_data->list, s);
    if (bed_sm != NULL) {
        const SCDetectByteExtractData *bed = (const SCDetectByteExtractData *)bed_sm->ctx;
        *local_id = bed->local_id;
        /* In string mode nbytes is the count of input characters parsed, not the
         * byte width of the resulting value, so it is not a usable key width;
         * report 0 and let the caller require an explicit width. */
        *nbytes = (bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) ? 0 : bed->nbytes;
        return true;
    }

    /* a byte_math result is a computed value with no inherent width, so report
     * 0 and let the caller require an explicit width. */
    SigMatch *bmd_sm = DetectByteMathRetrieveSMVar(name, s->init_data->list, s);
    if (bmd_sm != NULL) {
        *local_id = ((const DetectByteMathData *)bmd_sm->ctx)->local_id;
        *nbytes = 0;
        return true;
    }
    return false;
}

uint64_t SCDetectEngineThreadCtxGetByteVar(const DetectEngineThreadCtx *det_ctx, uint8_t id)
{
    return det_ctx->byte_values[id];
}
