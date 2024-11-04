/* Copyright (C) 2007-2017 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-hash-string.h"

/* djb2 string hashing */
uint32_t StringHashDjb2(const uint8_t *data, uint32_t datalen)
{
    uint32_t hash = 5381;
    for (uint32_t i = 0; i < datalen; i++) {
        uint32_t c = data[i];
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

/* djb2 string hashing */
uint32_t StringHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    return StringHashDjb2(data, datalen) % ht->array_size;
}

char StringHashCompareFunc(void *data1, uint16_t datalen1,
                           void *data2, uint16_t datalen2)
{
    size_t len1 = strlen((char *)data1);
    size_t len2 = strlen((char *)data2);

    if (len1 == len2 && memcmp(data1, data2, len1) == 0) {
        return 1;
    }

    return 0;
}

void StringHashFreeFunc(void *data)
{
    SCFree(data);
}
