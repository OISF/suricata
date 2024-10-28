/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Jim Xu <jim.xu@windriver.com>
 * \author Justin Viiret <justin.viiret@intel.com>
 * \author Lukas Sismis <lsismis@oisf.net>
 *
 * MPM pattern matcher core function for the Hyperscan regex matcher.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-mpm-hs-core.h"

#ifdef BUILD_HYPERSCAN

#include <hs.h>

// Encode major, minor, and patch into a single 32-bit integer.
#define HS_VERSION_ENCODE(major, minor, patch) (((major) << 24) | ((minor) << 16) | ((patch) << 8))
#define HS_VERSION_AT_LEAST(major, minor, patch)                                                   \
    (HS_VERSION_32BIT >= HS_VERSION_ENCODE(major, minor, patch))

/**
 * Translates Hyperscan error codes to human-readable messages.
 *
 * \param error_code
 *      The error code returned by a Hyperscan function.
 * \return
 *      A string describing the error.
 */
const char *HSErrorToStr(hs_error_t error_code)
{
    switch (error_code) {
        case HS_SUCCESS:
            return "HS_SUCCESS: The engine completed normally";
        case HS_INVALID:
            return "HS_INVALID: A parameter passed to this function was invalid";
        case HS_NOMEM:
            return "HS_NOMEM: A memory allocation failed";
        case HS_SCAN_TERMINATED:
            return "HS_SCAN_TERMINATED: The engine was terminated by callback";
        case HS_COMPILER_ERROR:
            return "HS_COMPILER_ERROR: The pattern compiler failed";
        case HS_DB_VERSION_ERROR:
            return "HS_DB_VERSION_ERROR: The given database was built for a different version of "
                   "Hyperscan";
        case HS_DB_PLATFORM_ERROR:
            return "HS_DB_PLATFORM_ERROR: The given database was built for a different platform "
                   "(i.e., CPU type)";
        case HS_DB_MODE_ERROR:
            return "HS_DB_MODE_ERROR: The given database was built for a different mode of "
                   "operation";
        case HS_BAD_ALIGN:
            return "HS_BAD_ALIGN: A parameter passed to this function was not correctly aligned";
        case HS_BAD_ALLOC:
            return "HS_BAD_ALLOC: The memory allocator did not return correctly aligned memory";
        case HS_SCRATCH_IN_USE:
            return "HS_SCRATCH_IN_USE: The scratch region was already in use";
#if HS_VERSION_AT_LEAST(4, 4, 0)
        case HS_ARCH_ERROR:
            return "HS_ARCH_ERROR: Unsupported CPU architecture";
#endif // HS_VERSION_AT_LEAST(4, 4, 0)
#if HS_VERSION_AT_LEAST(4, 6, 0)
        case HS_INSUFFICIENT_SPACE:
            return "HS_INSUFFICIENT_SPACE: Provided buffer was too small";
#endif // HS_VERSION_AT_LEAST(4, 6, 0)
#if HS_VERSION_AT_LEAST(5, 1, 1)
        case HS_UNKNOWN_ERROR:
            return "HS_UNKNOWN_ERROR: Unexpected internal error";
#endif // HS_VERSION_AT_LEAST(5, 1, 1)
        default:
            return "Unknown error code";
    }
}

#endif /* BUILD_HYPERSCAN */
