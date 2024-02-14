/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __HASH_H__
#define __HASH_H__

/* hash bucket structure */
typedef struct HashTableBucket_ {
    void *data;
    uint16_t size;
    struct HashTableBucket_ *next;
} HashTableBucket;

/* hash table structure */
typedef struct HashTable_ {
    HashTableBucket **array;
    uint32_t array_size;
#ifdef UNITTESTS
    uint32_t count;
#endif
    uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t);
    char (*Compare)(void *, uint16_t, void *, uint16_t);
    void (*Free)(void *);
} HashTable;

#define HASH_NO_SIZE 0

/* prototypes */
HashTable* HashTableInit(uint32_t, uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *));
void HashTableFree(HashTable *);
void HashTablePrint(HashTable *);
int HashTableAdd(HashTable *, void *, uint16_t);
int HashTableRemove(HashTable *, void *, uint16_t);
void *HashTableLookup(HashTable *, void *, uint16_t);
uint32_t HashTableGenericHash(HashTable *, void *, uint16_t);
char HashTableDefaultCompare(void *, uint16_t, void *, uint16_t);

void HashTableRegisterTests(void);

#endif /* __HASH_H__ */

