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

#ifndef SURICATA_HASHLIST_H
#define SURICATA_HASHLIST_H

/* hash bucket structure */
typedef struct HashListTableBucket_ {
    void *data;
    uint16_t size;
    struct HashListTableBucket_ *bucknext;
    struct HashListTableBucket_ *listnext;
    struct HashListTableBucket_ *listprev;
} HashListTableBucket;

/* hash table structure */
typedef struct HashListTable_ {
    HashListTableBucket **array;
    HashListTableBucket *listhead;
    HashListTableBucket *listtail;
    uint32_t array_size;
    uint32_t (*Hash)(struct HashListTable_ *, void *, uint16_t);
    char (*Compare)(void *, uint16_t, void *, uint16_t);
    void (*Free)(void *);
    void (*FreeWithCtx)(void *, void *);
} HashListTable;

/* prototypes */
HashListTable* HashListTableInit(uint32_t, uint32_t (*Hash)(struct HashListTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *));
HashListTable *HashListTableInitWithCtx(uint32_t,
        uint32_t (*Hash)(struct HashListTable_ *, void *, uint16_t),
        char (*Compare)(void *, uint16_t, void *, uint16_t), void (*FreeWithCtx)(void *, void *));

void HashListTableFreeWithCtx(void *, HashListTable *);
void HashListTableFree(HashListTable *);
int HashListTableAdd(HashListTable *, void *, uint16_t);
int HashListTableRemove(HashListTable *, void *, uint16_t);
void *HashListTableLookup(HashListTable *, void *, uint16_t);
uint32_t HashListTableGenericHash(HashListTable *, void *, uint16_t);
HashListTableBucket *HashListTableGetListHead(HashListTable *);
#define HashListTableGetListNext(hb) (hb)->listnext
#define HashListTableGetListData(hb) (hb)->data
char HashListTableDefaultCompare(void *, uint16_t, void *, uint16_t);

void HashListTableRegisterTests(void);

#endif /* SURICATA_HASHLIST_H */
