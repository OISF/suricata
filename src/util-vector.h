/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#ifndef __UTIL_VECTOR_H__
#define __UTIL_VECTOR_H__

#if defined(__SSE3__)

#include <pmmintrin.h>

typedef struct Vector_ {
    union {
        __m128i v;          /**< vector */
        uint8_t c[16];      /**< character */
        uint16_t w[8];      /**< word */
        uint32_t dw[4];     /**< double word */
        uint64_t qw[2];     /**< quad word */
    };
} Vector __attribute((aligned(16)));

#endif /* defined(__SSE3__) */

#endif /* __UTIL_VECTOR_H__ */
