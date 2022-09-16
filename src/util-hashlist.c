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
#ifdef UNITTESTS
#include "util-debug.h"
#include "util-unittest.h"
#endif
#include "util-hashlist.h"
#include "util-memcmp.h"

HashListTable* HashListTableInit(uint32_t size, uint32_t (*Hash)(struct HashListTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *)) {

    HashListTable *ht = NULL;

    if (size == 0) {
        goto error;
    }

    if (Hash == NULL) {
        //printf("ERROR: HashListTableInit no Hash function\n");
        goto error;
    }

    /* setup the filter */
    ht = SCMalloc(sizeof(HashListTable));
    if (unlikely(ht == NULL))
    goto error;
    memset(ht,0,sizeof(HashListTable));
    ht->array_size = size;
    ht->Hash = Hash;
    ht->Free = Free;

    if (Compare != NULL)
        ht->Compare = Compare;
    else
        ht->Compare = HashListTableDefaultCompare;

    /* setup the bitarray */
    ht->array = SCMalloc(ht->array_size * sizeof(HashListTableBucket *));
    if (ht->array == NULL)
        goto error;
    memset(ht->array,0,ht->array_size * sizeof(HashListTableBucket *));

    ht->listhead = NULL;
    ht->listtail = NULL;
    return ht;

error:
    if (ht != NULL) {
        if (ht->array != NULL)
            SCFree(ht->array);

        SCFree(ht);
    }
    return NULL;
}

void HashListTableFree(HashListTable *ht)
{
    uint32_t i = 0;

    if (ht == NULL)
        return;

    /* free the buckets */
    for (i = 0; i < ht->array_size; i++) {
        HashListTableBucket *hashbucket = ht->array[i];
        while (hashbucket != NULL) {
            HashListTableBucket *next_hashbucket = hashbucket->bucknext;
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            SCFree(hashbucket);
            hashbucket = next_hashbucket;
        }
    }

    /* free the array */
    if (ht->array != NULL)
        SCFree(ht->array);

    SCFree(ht);
}

void HashListTablePrint(HashListTable *ht)
{
    printf("\n----------- Hash Table Stats ------------\n");
    printf("Buckets:               %" PRIu32 "\n", ht->array_size);
    printf("Hash function pointer: %p\n", ht->Hash);
    printf("-----------------------------------------\n");
}

int HashListTableAdd(HashListTable *ht, void *data, uint16_t datalen)
{
    if (ht == NULL || data == NULL)
        return -1;

    uint32_t hash = ht->Hash(ht, data, datalen);

    SCLogDebug("ht %p hash %"PRIu32"", ht, hash);

    HashListTableBucket *hb = SCMalloc(sizeof(HashListTableBucket));
    if (unlikely(hb == NULL))
        goto error;
    memset(hb, 0, sizeof(HashListTableBucket));
    hb->data = data;
    hb->size = datalen;
    hb->bucknext = NULL;
    hb->listnext = NULL;
    hb->listprev = NULL;

    if (ht->array[hash] == NULL) {
        ht->array[hash] = hb;
    } else {
        hb->bucknext = ht->array[hash];
        ht->array[hash] = hb;
    }

    if (ht->listtail == NULL) {
        ht->listhead = hb;
        ht->listtail = hb;
    } else {
        hb->listprev = ht->listtail;
        ht->listtail->listnext = hb;
        ht->listtail = hb;
    }

    return 0;

error:
    return -1;
}

int HashListTableRemove(HashListTable *ht, void *data, uint16_t datalen)
{
    uint32_t hash = ht->Hash(ht, data, datalen);

    SCLogDebug("ht %p hash %"PRIu32"", ht, hash);

    if (ht->array[hash] == NULL) {
        SCLogDebug("ht->array[hash] NULL");
        return -1;
    }

    /* fast track for just one data part */
    if (ht->array[hash]->bucknext == NULL) {
        HashListTableBucket *hb = ht->array[hash];

        if (ht->Compare(hb->data,hb->size,data,datalen) == 1) {
            /* remove from the list */
            if (hb->listprev == NULL) {
                ht->listhead = hb->listnext;
            } else {
                hb->listprev->listnext = hb->listnext;
            }
            if (hb->listnext == NULL) {
                ht->listtail = hb->listprev;
            } else {
                hb->listnext->listprev = hb->listprev;
            }

            if (ht->Free != NULL)
                ht->Free(hb->data);

            SCFree(ht->array[hash]);
            ht->array[hash] = NULL;
            return 0;
        }

        SCLogDebug("fast track default case");
        return -1;
    }

    /* more data in this bucket */
    HashListTableBucket *hashbucket = ht->array[hash], *prev_hashbucket = NULL;
    do {
        if (ht->Compare(hashbucket->data,hashbucket->size,data,datalen) == 1) {

            /* remove from the list */
            if (hashbucket->listprev == NULL) {
                ht->listhead = hashbucket->listnext;
            } else {
                hashbucket->listprev->listnext = hashbucket->listnext;
            }
            if (hashbucket->listnext == NULL) {
                ht->listtail = hashbucket->listprev;
            } else {
                hashbucket->listnext->listprev = hashbucket->listprev;
            }

            if (prev_hashbucket == NULL) {
                /* root bucket */
                ht->array[hash] = hashbucket->bucknext;
            } else {
                /* child bucket */
                prev_hashbucket->bucknext = hashbucket->bucknext;
            }

            /* remove this */
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            SCFree(hashbucket);
            return 0;
        }

        prev_hashbucket = hashbucket;
        hashbucket = hashbucket->bucknext;
    } while (hashbucket != NULL);

    SCLogDebug("slow track default case");
    return -1;
}

char HashListTableDefaultCompare(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    if (len1 != len2)
        return 0;

    if (SCMemcmp(data1,data2,len1) != 0)
        return 0;

    return 1;
}

void *HashListTableLookup(HashListTable *ht, void *data, uint16_t datalen)
{

    if (ht == NULL) {
        SCLogDebug("Hash List table is NULL");
        return NULL;
    }

    uint32_t hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL) {
        return NULL;
    }

    HashListTableBucket *hashbucket = ht->array[hash];
    do {
        if (ht->Compare(hashbucket->data,hashbucket->size,data,datalen) == 1)
            return hashbucket->data;

        hashbucket = hashbucket->bucknext;
    } while (hashbucket != NULL);

    return NULL;
}

uint32_t HashListTableGenericHash(HashListTable *ht, void *data, uint16_t datalen)
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

HashListTableBucket *HashListTableGetListHead(HashListTable *ht)
{
    return ht->listhead;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
static int HashListTableTestInit01 (void)
{
    HashListTable *ht = HashListTableInit(1024, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    HashListTableFree(ht);
    return 1;
}

/* no hash function, so it should fail */
static int HashListTableTestInit02 (void)
{
    HashListTable *ht = HashListTableInit(1024, NULL, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashListTableFree(ht);
    return 0;
}

static int HashListTableTestInit03 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(1024, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    if (ht->Hash == HashListTableGenericHash)
        result = 1;

    HashListTableFree(ht);
    return result;
}

static int HashListTableTestInit04 (void)
{
    HashListTable *ht = HashListTableInit(0, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashListTableFree(ht);
    return 0;
}

static int HashListTableTestAdd01 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, (char *)"test", 0);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestAdd02 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, NULL, 4);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestAdd03 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, (char *)"test", 0);
    if (r != 0)
        goto end;

    if (ht->listhead == NULL) {
        printf("ht->listhead == NULL: ");
        goto end;
    }

    if (ht->listtail == NULL) {
        printf("ht->listtail == NULL: ");
        goto end;
    }

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestAdd04 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    char *rp = HashListTableLookup(ht, (char *)"test", 4);
    if (rp == NULL)
        goto end;

    HashListTableBucket *htb = HashListTableGetListHead(ht);
    if (htb == NULL) {
        printf("htb == NULL: ");
        goto end;
    }

    char *rp2 = HashListTableGetListData(htb);
    if (rp2 == NULL) {
        printf("rp2 == NULL: ");
        goto end;
    }

    if (rp != rp2) {
        printf("rp != rp2: ");
        goto end;
    }

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestFull01 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    char *rp = HashListTableLookup(ht, (char *)"test", 4);
    if (rp == NULL)
        goto end;

    r = HashListTableRemove(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestFull02 (void)
{
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    char *rp = HashListTableLookup(ht, (char *)"test", 4);
    if (rp == NULL)
        goto end;

    r = HashListTableRemove(ht, (char *)"test2", 5);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}
#endif /* UNITTESTS */

void HashListTableRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HashListTableTestInit01", HashListTableTestInit01);
    UtRegisterTest("HashListTableTestInit02", HashListTableTestInit02);
    UtRegisterTest("HashListTableTestInit03", HashListTableTestInit03);
    UtRegisterTest("HashListTableTestInit04", HashListTableTestInit04);

    UtRegisterTest("HashListTableTestAdd01", HashListTableTestAdd01);
    UtRegisterTest("HashListTableTestAdd02", HashListTableTestAdd02);
    UtRegisterTest("HashListTableTestAdd03", HashListTableTestAdd03);
    UtRegisterTest("HashListTableTestAdd04", HashListTableTestAdd04);

    UtRegisterTest("HashListTableTestFull01", HashListTableTestFull01);
    UtRegisterTest("HashListTableTestFull02", HashListTableTestFull02);
#endif /* UNITTESTS */
}

