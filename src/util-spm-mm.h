/* Copyright (C) 2024 Open Information Security Foundation
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
 */

#ifndef SURICATA_UTIL_SPM_MM
#define SURICATA_UTIL_SPM_MM

#ifdef HAVE_MEMMEM

typedef struct SpmMmCtx_ {
    uint32_t needle_len;
    int nocase;
    uint8_t needle[];
} SpmMmCtx;

uint8_t *MMScan(const SpmCtx *ctx, SpmThreadCtx *_thread_ctx, const uint8_t *haystack,
        uint32_t haystack_len);

#endif /* HAVE_MEMMEM */

void SpmMMRegister(void);

#endif /* SURICATA_UTIL_SPM_MM */
