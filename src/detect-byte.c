/* Copyright (C) 2020-2025 Open Information Security Foundation
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

// Once a variable is found, apply strict semantics (error) else warning
static bool DetectByteListMismatch(bool any, int sm_list, int found_list, bool strict,
        const char *arg, const DetectEngineCtx *de_ctx)
{
    if (any || sm_list == found_list)
        return false;

    if (strict) {
        return true;
    }

    if (de_ctx) {
        SCLogWarning("Using byte variable from a different buffer may produce indeterminate "
                     "results; variable: \"%s\" at line %" PRId32 " from file %s; see issue #1412",
                arg, de_ctx->rule_line, de_ctx->rule_file);
    }
    return false;
}

/**
 * \brief Used to retrieve args from BM.
 *
 * \param arg The name of the variable being sought
 * \param s The signature to check for the variable
 * \param strict Match if and only iff the list sought and the list found equal.
 * \param sm_list The caller's matching buffer
 * \param index When found, the value of the slot within the byte vars
 *
 * \retval true A match for the variable was found.
 * \retval false
 */
bool DetectByteRetrieveSMVar(const char *arg, const Signature *s, bool strict, int sm_list,
        DetectByteIndexType *index, const DetectEngineCtx *de_ctx)
{
    bool any = sm_list == -1;
    int found_list;
    const SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(arg, &found_list, s);
    if (bed_sm != NULL) {
        if (DetectByteListMismatch(any, sm_list, found_list, strict, arg, de_ctx)) {
            return false;
        }

        SCLogDebug("[buf] found %s; list wanted: sm_list: %d, list found: %d", arg, sm_list,
                found_list);
        *index = ((SCDetectByteExtractData *)bed_sm->ctx)->local_id;
        return true;
    }

    const SigMatch *bmd_sm = DetectByteMathRetrieveSMVar(arg, &found_list, s);
    if (bmd_sm != NULL) {
        if (!DetectByteListMismatch(any, sm_list, found_list, strict, arg, de_ctx)) {
            *index = ((DetectByteMathData *)bmd_sm->ctx)->local_id;
            SCLogDebug("[list] found %s; list wanted: sm_list: %d, list found: %d", arg, sm_list,
                    found_list);
            return true;
        }
    }

    return false;
}
