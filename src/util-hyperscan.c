/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Justin Viiret <justin.viiret@intel.com>
 *
 * Support functions for Hyperscan library integration.
 */

#include "suricata-common.h"

#ifdef BUILD_HYPERSCAN
#include "util-hyperscan.h"

/**
 * \internal
 * \brief Convert a pattern into a regex string accepted by the Hyperscan
 * compiler.
 *
 * For simplicity, we just take each byte of the original pattern and render it
 * with a hex escape (i.e. ' ' -> "\x20")/
 */
char *HSRenderPattern(const uint8_t *pat, uint16_t pat_len)
{
    if (pat == NULL) {
        return NULL;
    }
    const size_t hex_len = (pat_len * 4) + 1;
    char *str = SCMalloc(hex_len);
    if (str == NULL) {
        return NULL;
    }
    memset(str, 0, hex_len);
    char *sp = str;
    for (uint16_t i = 0; i < pat_len; i++) {
        snprintf(sp, 5, "\\x%02x", pat[i]);
        sp += 4;
    }
    *sp = '\0';
    return str;
}

#endif /* BUILD_HYPERSCAN */
