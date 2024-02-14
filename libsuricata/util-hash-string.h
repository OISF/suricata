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

#ifndef __UTIL_HASH_STRING_H__
#define __UTIL_HASH_STRING_H__

#include "util-hash.h"

uint32_t StringHashDjb2(const uint8_t *data, uint32_t datalen);
uint32_t StringHashFunc(HashTable *ht, void *data, uint16_t datalen);
char StringHashCompareFunc(void *data1, uint16_t datalen1,
                           void *data2, uint16_t datalen2);
void StringHashFreeFunc(void *data);

#endif /* __UTIL_HASH_STRING_H__ */
