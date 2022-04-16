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
 *
 * Chained read only hash table implementation, meaning that
 * after the initial fill no changes are allowed.
 *
 * Loading takes 2 stages.
 * - stage1 maps data
 * - stage2 fills blob
 *
 * \todo a bloomfilter in the ROHashTableOffsets could possibly prevent
 *       a lot of cache misses when validating a potential match
 *
 * \todo maybe add a user ctx to be returned instead, something like a
 *       4/8 byte ptr or simply a flag
 */

#include "suricata-common.h"
#include "util-hash.h"
#include "util-unittest.h"
#include "util-memcmp.h"
#include "util-hash-lookup3.h"
#include "queue.h"
#include "util-rohash.h"

/** item_size data beyond this header */
typedef struct ROHashTableItem_ {
    uint32_t pos;       /**< position relative to other values with same hash */
    TAILQ_ENTRY(ROHashTableItem_) next;
} ROHashTableItem;

/** offset table */
typedef struct ROHashTableOffsets_ {
    uint32_t cnt;       /**< number of items for this hash */
    uint32_t offset;    /**< position in the blob of the first item */
} ROHashTableOffsets;

/** \brief initialize a new rohash
 *
 *  \param hash_bits hash size as 2^hash_bits, so power of 2, max 31
 *  \param item_size size of the data to store
 *
 *  \retval table ptr or NULL on error
 */
ROHashTable *ROHashInit(uint8_t hash_bits, uint16_t item_size)
{
    if (item_size % 4 != 0 || item_size == 0) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "data size must be multiple of 4");
        return NULL;
    }
    if (hash_bits < 4 || hash_bits > 31) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "invalid hash_bits setting, valid range is 4-31");
        return NULL;
    }

    uint32_t size = hashsize(hash_bits) * sizeof(ROHashTableOffsets);

    ROHashTable *table = SCMalloc(sizeof(ROHashTable) + size);
    if (unlikely(table == NULL)) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "failed to alloc memory");
        return NULL;
    }
    memset(table, 0, sizeof(ROHashTable) + size);

    table->items = 0;
    table->item_size = item_size;
    table->hash_bits = hash_bits;
    TAILQ_INIT(&table->head);

    return table;
}

void ROHashFree(ROHashTable *table)
{
    if (table != NULL) {
        if (table->data != NULL) {
            SCFree(table->data);
        }

        SCFree(table);
    }
}

uint32_t ROHashMemorySize(ROHashTable *table)
{
    uint32_t r1 = hashsize(table->hash_bits) * sizeof(ROHashTableOffsets);
    uint32_t r2 = table->items * table->item_size;
    return (uint32_t)(r1 + r2 + sizeof(ROHashTable));
}

/**
 *  \retval NULL not found
 *  \retval ptr found
 */
void *ROHashLookup(ROHashTable *table, void *data, uint16_t size)
{
    if (data == NULL || size != table->item_size) {
        SCReturnPtr(NULL, "void");
    }

    uint32_t hash = hashword(data, table->item_size/4, 0) & hashmask(table->hash_bits);

    /* get offsets start */
    ROHashTableOffsets *os = (void *)table + sizeof(ROHashTable);
    ROHashTableOffsets *o = &os[hash];

    /* no matches */
    if (o->cnt == 0) {
        SCReturnPtr(NULL, "void");
    }

    uint32_t u;
    for (u = 0; u < o->cnt; u++) {
        uint32_t offset = (o->offset + u) * table->item_size;

        if (SCMemcmp(table->data + offset, data, table->item_size) == 0) {
            SCReturnPtr(table->data + offset, "void");
        }
    }
    SCReturnPtr(NULL, "void");
}

/** \brief Add a new value to the hash
 *
 *  \note can only be done when table isn't in a locked state yet
 *
 *  \param table the hash table
 *  \param value value to add
 *  \param size value size. *MUST* match table item_size
 *
 *  \retval 0 error
 *  \retval 1 ok
 */
int ROHashInitQueueValue(ROHashTable *table, void *value, uint16_t size)
{
    if (table->locked) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "can't add value to locked table");
        return 0;
    }
    if (table->item_size != size) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "wrong size for data %u != %u", size, table->item_size);
        return 0;
    }

    ROHashTableItem *item = SCMalloc(sizeof(ROHashTableItem) + table->item_size);
    if (item != NULL) {
        memset(item, 0x00, sizeof(ROHashTableItem));
        memcpy((void *)item + sizeof(ROHashTableItem), value, table->item_size);
        TAILQ_INSERT_TAIL(&table->head, item, next);
        return 1;
    }

    return 0;
}

/** \brief create final hash data structure
 *
 *  \param table the hash table
 *
 *  \retval 0 error
 *  \retval 1 ok
 *
 *  \note after this call the nothing can be added to the hash anymore.
 */
int ROHashInitFinalize(ROHashTable *table)
{
    if (table->locked) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "table already locked");
        return 0;
    }

    ROHashTableItem *item = NULL;
    ROHashTableOffsets *os = (void *)table + sizeof(ROHashTable);

    /* count items per hash value */
    TAILQ_FOREACH(item, &table->head, next) {
        uint32_t hash = hashword((void *)item + sizeof(*item), table->item_size/4, 0) & hashmask(table->hash_bits);
        ROHashTableOffsets *o = &os[hash];

        item->pos = o->cnt;
        o->cnt++;
        table->items++;
    }

    if (table->items == 0) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "no items");
        return 0;
    }

    /* get the data block */
    uint32_t newsize = table->items * table->item_size;
    table->data = SCMalloc(newsize);
    if (table->data == NULL) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "failed to alloc memory");
        return 0;
    }
    memset(table->data, 0x00, newsize);

    /* calc offsets into the block per hash value */
    uint32_t total = 0;
    uint32_t x;
    for (x = 0; x < hashsize(table->hash_bits); x++) {
        ROHashTableOffsets *o = &os[x];

        if (o->cnt == 0)
            continue;

        o->offset = total;
        total += o->cnt;
    }

    /* copy each value into the data block */
    TAILQ_FOREACH(item, &table->head, next) {
        uint32_t hash = hashword((void *)item + sizeof(*item), table->item_size/4, 0) & hashmask(table->hash_bits);

        ROHashTableOffsets *o = &os[hash];
        uint32_t offset = (o->offset + item->pos) * table->item_size;

        memcpy(table->data + offset, (void *)item + sizeof(*item), table->item_size);

    }

    /* clean up temp items */
    while ((item = TAILQ_FIRST(&table->head))) {
        TAILQ_REMOVE(&table->head, item, next);
        SCFree(item);
    }

    table->locked = 1;
    return 1;
}
