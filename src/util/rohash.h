/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#ifndef __UTIL_ROHASH_H__
#define __UTIL_ROHASH_H__

#include "queue.h"

typedef struct ROHashTable_ {
    uint8_t locked;
    uint8_t hash_bits;
    uint16_t item_size;
    uint32_t items;
    void *data;
    TAILQ_HEAD(, ROHashTableItem_) head;
} ROHashTable;

/* init time */
ROHashTable *ROHashInit(uint8_t hash_bits, uint16_t item_size);
int ROHashInitFinalize(ROHashTable *table);
void ROHashFree(ROHashTable *table);
int ROHashInitQueueValue(ROHashTable *table, void *value, uint16_t size);
uint32_t ROHashMemorySize(ROHashTable *table);

/* run time */
void *ROHashLookup(ROHashTable *table, void *data, uint16_t size);

#endif /* __UTIL_ROHASH_H__ */
