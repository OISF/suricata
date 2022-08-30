/* Copyright (C) 2017-2022 Open Information Security Foundation
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

#ifndef __DATASETS_STRING_H__
#define __DATASETS_STRING_H__

#include "datasets-reputation.h"

typedef struct StringType {
    uint32_t len;
    DataRepType rep;
    uint8_t *ptr;
} StringType;

int StringSet(void *dst, void *src);
bool StringCompare(void *a, void *b);
uint32_t StringHash(void *s);
void StringFree(void *s);
int StringAsBase64(const void *s, char *out, size_t out_size);

#endif /* __DATASETS_STRING_H__ */
