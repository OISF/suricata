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
 *
 * Chained hash table implementation
 *
 * The 'Free' pointer can be used to have the API free your
 * hashed data. If it's NULL it's the callers responsebility
 */

#include "suricata-common.h"
#include "util-hash.h"
#include "util-unittest.h"
#include "util-memcmp.h"

HashTable* HashTableInit(uint32_t size, uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *)) {

    HashTable *ht = NULL;

    if (size == 0) {
        goto error;
    }

    if (Hash == NULL) {
        //printf("ERROR: HashTableInit no Hash function\n");
        goto error;
    }

    /* setup the filter */
    ht = SCMalloc(sizeof(HashTable));
    if (unlikely(ht == NULL))
    goto error;
    memset(ht,0,sizeof(HashTable));
    ht->array_size = size;
    ht->Hash = Hash;
    ht->Free = Free;

    if (Compare != NULL)
        ht->Compare = Compare;
    else
        ht->Compare = HashTableDefaultCompare;

    /* setup the bitarray */
    ht->array = SCMalloc(ht->array_size * sizeof(HashTableBucket *));
    if (ht->array == NULL)
        goto error;
    memset(ht->array,0,ht->array_size * sizeof(HashTableBucket *));

    return ht;

error:
    if (ht != NULL) {
        if (ht->array != NULL)
            SCFree(ht->array);

        SCFree(ht);
    }
    return NULL;
}

void HashTableFree(HashTable *ht)
{
    uint32_t i = 0;

    if (ht == NULL)
        return;

    /* free the buckets */
    for (i = 0; i < ht->array_size; i++) {
        HashTableBucket *hashbucket = ht->array[i];
        while (hashbucket != NULL) {
            HashTableBucket *next_hashbucket = hashbucket->next;
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            SCFree(hashbucket);
            hashbucket = next_hashbucket;
        }
    }

    /* free the arrray */
    if (ht->array != NULL)
        SCFree(ht->array);

    SCFree(ht);
}

void HashTablePrint(HashTable *ht)
{
    printf("\n----------- Hash Table Stats ------------\n");
    printf("Buckets:               %" PRIu32 "\n", ht->array_size);
    printf("Hash function pointer: %p\n", ht->Hash);
    printf("-----------------------------------------\n");
}

int HashTableAdd(HashTable *ht, void *data, uint16_t datalen)
{
    if (ht == NULL || data == NULL)
        return -1;

    uint32_t hash = ht->Hash(ht, data, datalen);

    HashTableBucket *hb = SCMalloc(sizeof(HashTableBucket));
    if (unlikely(hb == NULL))
        goto error;
    memset(hb, 0, sizeof(HashTableBucket));
    hb->data = data;
    hb->size = datalen;
    hb->next = NULL;

    if (ht->array[hash] == NULL) {
        ht->array[hash] = hb;
    } else {
        hb->next = ht->array[hash];
        ht->array[hash] = hb;
    }

#ifdef UNITTESTS
    ht->count++;
#endif

    return 0;

error:
    return -1;
}

int HashTableRemove(HashTable *ht, void *data, uint16_t datalen)
{
    uint32_t hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL) {
        return -1;
    }

    if (ht->array[hash]->next == NULL) {
        if (ht->Free != NULL)
            ht->Free(ht->array[hash]->data);
        SCFree(ht->array[hash]);
        ht->array[hash] = NULL;
        return 0;
    }

    HashTableBucket *hashbucket = ht->array[hash], *prev_hashbucket = NULL;
    do {
        if (ht->Compare(hashbucket->data,hashbucket->size,data,datalen) == 1) {
            if (prev_hashbucket == NULL) {
                /* root bucket */
                ht->array[hash] = hashbucket->next;
            } else {
                /* child bucket */
                prev_hashbucket->next = hashbucket->next;
            }

            /* remove this */
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            SCFree(hashbucket);
            return 0;
        }

        prev_hashbucket = hashbucket;
        hashbucket = hashbucket->next;
    } while (hashbucket != NULL);

    return -1;
}

void *HashTableLookup(HashTable *ht, void *data, uint16_t datalen)
{
    uint32_t hash = 0;

    if (ht == NULL)
        return NULL;

    hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL)
        return NULL;

    HashTableBucket *hashbucket = ht->array[hash];
    do {
        if (ht->Compare(hashbucket->data, hashbucket->size, data, datalen) == 1)
            return hashbucket->data;

        hashbucket = hashbucket->next;
    } while (hashbucket != NULL);

    return NULL;
}

uint32_t HashTableGenericHash(HashTable *ht, void *data, uint16_t datalen)
{
     uint8_t *d = (uint8_t *)data;
     uint32_t i;
     uint32_t hash = 0;

     for (i = 0; i < datalen; i++) {
         if (i == 0)      hash += (((uint32_t)*d++));
         else if (i == 1) hash += (((uint32_t)*d++) * datalen);
         else             hash *= (((uint32_t)*d++) * i) + datalen + i;
     }

     hash *= datalen;
     hash %= ht->array_size;
     return hash;
}

char HashTableDefaultCompare(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    if (len1 != len2)
        return 0;

    if (SCMemcmp(data1,data2,len1) != 0)
        return 0;

    return 1;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
static int HashTableTestInit01 (void)
{
    HashTable *ht = HashTableInit(1024, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    HashTableFree(ht);
    return 1;
}

/* no hash function, so it should fail */
static int HashTableTestInit02 (void)
{
    HashTable *ht = HashTableInit(1024, NULL, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashTableFree(ht);
    return 0;
}

static int HashTableTestInit03 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(1024, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    if (ht->Hash == HashTableGenericHash)
        result = 1;

    HashTableFree(ht);
    return result;
}

static int HashTableTestInit04 (void)
{
    HashTable *ht = HashTableInit(0, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashTableFree(ht);
    return 0;
}

static int HashTableTestInit05 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(1024, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    if (ht->Compare == HashTableDefaultCompare)
        result = 1;

    HashTableFree(ht);
    return result;
}

static char HashTableDefaultCompareTest(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    if (len1 != len2)
        return 0;

    if (SCMemcmp(data1,data2,len1) != 0)
        return 0;

    return 1;
}

static int HashTableTestInit06 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(1024, HashTableGenericHash, HashTableDefaultCompareTest, NULL);
    if (ht == NULL)
        return 0;

    if (ht->Compare == HashTableDefaultCompareTest)
        result = 1;

    HashTableFree(ht);
    return result;
}

static int HashTableTestAdd01 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(32, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashTableAdd(ht, "test", 0);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashTableFree(ht);
    return result;
}

static int HashTableTestAdd02 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(32, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashTableAdd(ht, NULL, 4);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashTableFree(ht);
    return result;
}

static int HashTableTestFull01 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(32, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashTableAdd(ht, "test", 4);
    if (r != 0)
        goto end;

    char *rp = HashTableLookup(ht, "test", 4);
    if (rp == NULL)
        goto end;

    r = HashTableRemove(ht, "test", 4);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashTableFree(ht);
    return result;
}

static int HashTableTestFull02 (void)
{
    int result = 0;
    HashTable *ht = HashTableInit(32, HashTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashTableAdd(ht, "test", 4);
    if (r != 0)
        goto end;

    char *rp = HashTableLookup(ht, "test", 4);
    if (rp == NULL)
        goto end;

    r = HashTableRemove(ht, "test2", 5);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashTableFree(ht);
    return result;
}
#endif

void HashTableRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HashTableTestInit01", HashTableTestInit01, 1);
    UtRegisterTest("HashTableTestInit02", HashTableTestInit02, 1);
    UtRegisterTest("HashTableTestInit03", HashTableTestInit03, 1);
    UtRegisterTest("HashTableTestInit04", HashTableTestInit04, 1);
    UtRegisterTest("HashTableTestInit05", HashTableTestInit05, 1);
    UtRegisterTest("HashTableTestInit06", HashTableTestInit06, 1);

    UtRegisterTest("HashTableTestAdd01", HashTableTestAdd01, 1);
    UtRegisterTest("HashTableTestAdd02", HashTableTestAdd02, 1);

    UtRegisterTest("HashTableTestFull01", HashTableTestFull01, 1);
    UtRegisterTest("HashTableTestFull02", HashTableTestFull02, 1);
#endif
}

