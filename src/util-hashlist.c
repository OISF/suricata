/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

/* Chained hash table implementation
 *
 * The 'Free' pointer can be used to have the API free your
 * hashed data. If it's NULL it's the callers responsebility */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "util-hashlist.h"

#include "util-unittest.h"

HashListTable* HashListTableInit(u_int32_t size, u_int32_t (*Hash)(struct _HashListTable *, void *, u_int16_t), char (*Compare)(void *, u_int16_t, void *, u_int16_t), void (*Free)(void *)) {

    HashListTable *ht = NULL;

    if (size == 0) {
        goto error;
    }

    if (Hash == NULL) {
        //printf("ERROR: HashListTableInit no Hash function\n");
        goto error;
    }

    /* setup the filter */
    ht = malloc(sizeof(HashListTable));
    if (ht == NULL)
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
    ht->array = malloc(ht->array_size * sizeof(HashListTableBucket *));
    if (ht->array == NULL)
        goto error;
    memset(ht->array,0,ht->array_size * sizeof(HashListTableBucket *));

    ht->listhead = NULL;
    ht->listtail = NULL;
    return ht;

error:
    if (ht != NULL) {
        if (ht->array != NULL)
            free(ht->array);

        free(ht);
    }
    return NULL;
}

void HashListTableFree(HashListTable *ht) {
    u_int32_t i = 0;

    if (ht == NULL)
        return;

    /* free the buckets */
    for (i = 0; i < ht->array_size; i++) {
        HashListTableBucket *hashbucket = ht->array[i];
        while (hashbucket != NULL) {
            HashListTableBucket *next_hashbucket = hashbucket->bucknext;
            if (ht->Free != NULL)
                ht->Free(hashbucket->data);
            free(hashbucket);
            hashbucket = next_hashbucket;
        }
    }

    /* free the arrray */
    if (ht->array != NULL)
        free(ht->array);

    free(ht);
}

void HashListTablePrint(HashListTable *ht) {
    printf("\n----------- Hash Table Stats ------------\n");
    printf("Buckets:               %u\n", ht->array_size);
    printf("Hash function pointer: %p\n", ht->Hash);
    printf("-----------------------------------------\n");
}

int HashListTableAdd(HashListTable *ht, void *data, u_int16_t datalen) {
    if (ht == NULL || data == NULL)
        return -1;

    u_int32_t hash = ht->Hash(ht, data, datalen);

    HashListTableBucket *hb = malloc(sizeof(HashListTableBucket));
    if (hb == NULL) {
        goto error;
    }
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
        ht->listtail->listnext = hb;
        hb->listprev = ht->listtail->listnext;
        ht->listtail = hb;
    }

    return 0;

error:
    return -1;
}

int HashListTableRemove(HashListTable *ht, void *data, u_int16_t datalen) {
    u_int32_t hash = ht->Hash(ht, data, datalen);

    if (ht->array[hash] == NULL) {
        return -1;
    }

    if (ht->array[hash]->bucknext == NULL) {
        if (ht->Free != NULL)
            ht->Free(ht->array[hash]->data);
        free(ht->array[hash]);
        ht->array[hash] = NULL;
        return 0;
    }

    HashListTableBucket *hashbucket = ht->array[hash], *prev_hashbucket = NULL;
    do {
        if (hashbucket->size != datalen) {
            prev_hashbucket = hashbucket;
            hashbucket = hashbucket->bucknext;
            continue;
        }

        if (memcmp(hashbucket->data,data,datalen) == 0) {
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
            free(hashbucket);
            return 0;
        }

        prev_hashbucket = hashbucket;
        hashbucket = hashbucket->bucknext;
    } while (hashbucket != NULL);

    return -1;
}

char HashListTableDefaultCompare(void *data1, u_int16_t len1, void *data2, u_int16_t len2) {
    if (len1 != len2)
        return 0;

    if (memcmp(data1,data2,len1) != 0)
        return 0;

    return 1;
}

void *HashListTableLookup(HashListTable *ht, void *data, u_int16_t datalen) {
    u_int32_t hash = ht->Hash(ht, data, datalen);

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

u_int32_t HashListTableGenericHash(HashListTable *ht, void *data, u_int16_t datalen) {
     u_int8_t *d = (u_int8_t *)data;
     u_int32_t i;
     u_int32_t hash = 0;

     for (i = 0; i < datalen; i++) {
         if (i == 0)      hash += (((u_int32_t)*d++));
         else if (i == 1) hash += (((u_int32_t)*d++) * datalen);
         else             hash *= (((u_int32_t)*d++) * i) + datalen + i;
     }

     hash *= datalen;
     hash %= ht->array_size;
     return hash;
}

HashListTableBucket *HashListTableGetListHead(HashListTable *ht) {
    return ht->listhead;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

static int HashListTableTestInit01 (void) {
    HashListTable *ht = HashListTableInit(1024, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    HashListTableFree(ht);
    return 1;
}

/* no hash function, so it should fail */
static int HashListTableTestInit02 (void) {
    HashListTable *ht = HashListTableInit(1024, NULL, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashListTableFree(ht);
    return 0;
}

static int HashListTableTestInit03 (void) {
    int result = 0;
    HashListTable *ht = HashListTableInit(1024, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 0;

    if (ht->Hash == HashListTableGenericHash)
        result = 1;

    HashListTableFree(ht);
    return result;
}

static int HashListTableTestInit04 (void) {
    HashListTable *ht = HashListTableInit(0, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        return 1;

    HashListTableFree(ht);
    return 0;
}

static int HashListTableTestAdd01 (void) {
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, "test", 0);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestAdd02 (void) {
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

static int HashListTableTestFull01 (void) {
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, "test", 4);
    if (r != 0)
        goto end;

    char *rp = HashListTableLookup(ht, "test", 4);
    if (rp == NULL)
        goto end;

    r = HashListTableRemove(ht, "test", 4);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

static int HashListTableTestFull02 (void) {
    int result = 0;
    HashListTable *ht = HashListTableInit(32, HashListTableGenericHash, NULL, NULL);
    if (ht == NULL)
        goto end;

    int r = HashListTableAdd(ht, "test", 4);
    if (r != 0)
        goto end;

    char *rp = HashListTableLookup(ht, "test", 4);
    if (rp == NULL)
        goto end;

    r = HashListTableRemove(ht, "test2", 5);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (ht != NULL) HashListTableFree(ht);
    return result;
}

void HashListTableRegisterTests(void) {
    UtRegisterTest("HashListTableTestInit01", HashListTableTestInit01, 1);
    UtRegisterTest("HashListTableTestInit02", HashListTableTestInit02, 1);
    UtRegisterTest("HashListTableTestInit03", HashListTableTestInit03, 1);
    UtRegisterTest("HashListTableTestInit04", HashListTableTestInit04, 1);

    UtRegisterTest("HashListTableTestAdd01", HashListTableTestAdd01, 1);
    UtRegisterTest("HashListTableTestAdd02", HashListTableTestAdd02, 1);

    UtRegisterTest("HashListTableTestFull01", HashListTableTestFull01, 1);
    UtRegisterTest("HashListTableTestFull02", HashListTableTestFull02, 1);
}

