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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef SURICATA_DATAJSON_STRING_H
#define SURICATA_DATAJSON_STRING_H

typedef struct StringTypeJson {
    uint32_t len;
    DataJsonType json;
    uint8_t *ptr;
} StringTypeJson;

int StringJsonSet(void *dst, void *src);
bool StringJsonCompare(void *a, void *b);
uint32_t StringJsonHash(uint32_t hash_seed, void *s);
void StringJsonFree(void *s);
int StringJsonAsBase64(const void *s, char *out, size_t out_size);

#endif
