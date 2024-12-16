/* Copyright (C) 2017-2019 Open Information Security Foundation
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

#ifndef SURICATA_DATASETS_STRING_H
#define SURICATA_DATASETS_STRING_H

#include "datasets-reputation.h"

typedef struct StringType {
    uint32_t len;
    DataRepType rep;
    uint8_t *ptr;
} StringType;

typedef struct StringTypeJson {
    uint32_t len;
    DataJsonType json;
    uint8_t *ptr;
} StringTypeJson;

int StringSet(void *dst, void *src);
bool StringCompare(void *a, void *b);
uint32_t StringHash(uint32_t hash_seed, void *s);
uint32_t StringGetLength(void *s);
void StringFree(void *s);
int StringAsBase64(const void *s, char *out, size_t out_size);

int StringJsonSet(void *dst, void *src);
bool StringJsonCompare(void *a, void *b);
uint32_t StringJsonHash(uint32_t hash_seed, void *s);
void StringJsonFree(void *s);
int StringJsonAsBase64(const void *s, char *out, size_t out_size);

#endif /* SURICATA_DATASETS_STRING_H */
