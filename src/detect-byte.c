/* Copyright (C) 2020 Open Information Security Foundation
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
#include "detect.h"
#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-bytemath.h"

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

/**
 * \brief Resolve a byte_extract or byte_math variable by name.
 *
 * Wrapper around DetectByteRetrieveSMVar that searches all buffers.
 *
 * \param name Variable name to look up
 * \param s The signature containing the variable
 * \param index Output: local_id index into byte_values
 *
 * \retval true if the variable was found
 * \retval false otherwise
 */
bool SCDetectByteRetrieveVarInfo(const char *name, const Signature *s, DetectByteIndexType *index)
{
    return DetectByteRetrieveSMVar(name, s, -1, index);
}

/**
 * \brief Get a byte_extract variable's buffer offset for pre-transform extraction.
 *
 * Searches only the current buffer (s->init_data->curbuf) to ensure the
 * byte_extract variable is on the same buffer as the transform referencing it.
 *
 * Returns the byte_extract's absolute buffer offset so the xor transform
 * can read key bytes directly from the inspection buffer. This is a
 * workaround until a general pre-transform extraction phase is added
 * to the detection engine.
 *
 * Only works for byte_extract variables with absolute (non-relative) offsets
 * on the same buffer as the calling transform.
 *
 * \param name Variable name to look up
 * \param s The signature being set up (uses curbuf for buffer matching)
 * \param offset Output: the absolute buffer offset
 * \param nbytes Output: the number of bytes to extract
 *
 * \retval true if the variable was found on the current buffer with an absolute offset
 * \retval false otherwise
 */
bool SCDetectByteExtractGetBufferOffset(
        const char *name, const Signature *s, int16_t *offset, uint8_t *nbytes)
{
    if (s->init_data == NULL || s->init_data->curbuf == NULL)
        return false;

    /* Search only the current buffer's SigMatch chain to ensure the
     * byte_extract variable is on the same buffer as the transform. */
    SigMatch *sm = s->init_data->curbuf->head;
    while (sm != NULL) {
        if (sm->type == DETECT_BYTE_EXTRACT) {
            const SCDetectByteExtractData *bed = (const SCDetectByteExtractData *)sm->ctx;
            if (strcmp(bed->name, name) == 0) {
                if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
                    return false;
                }
                *offset = bed->offset;
                *nbytes = bed->nbytes;
                return true;
            }
        }
        sm = sm->next;
    }
    return false;
}
