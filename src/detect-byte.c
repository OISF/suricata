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
#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-bytemath.h"
#include "rust.h"
/**
 * \brief Used to retrieve args from BM.
 *
 * \param arg The name of the variable being sought
 * \param s The signature to check for the variable
 * \param index When found, the value of the slot within the byte vars
 *
 * \retval true A match for the variable was found.
 * \retval false
 */
bool DetectByteRetrieveSMVar(const char *arg, const Signature *s, DetectByteIndexType *index)
{
    SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(arg, s);
    if (bed_sm != NULL) {
        *index = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
        return true;
    }

    SigMatch *bmd_sm = DetectByteMathRetrieveSMVar(arg, s);
    if (bmd_sm != NULL) {
        *index = ((DetectByteMathData *)bmd_sm->ctx)->local_id;
        return true;
    }
    return false;
}
