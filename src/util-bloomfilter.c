/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

/* Bitwise bloom filter implementation. */

#include "suricata-common.h"
#include "util-bloomfilter.h"
#include "util-unittest.h"

BloomFilter *BloomFilterInit(uint32_t size, uint8_t iter, uint32_t (*Hash)(void *, uint16_t, uint8_t, uint32_t)) {
    BloomFilter *bf = NULL;

    if (size == 0 || iter == 0)
        goto error;

    if (Hash == NULL) {
        //printf("ERROR: BloomFilterInit no Hash function\n");
        goto error;
    }

    /* setup the filter */
    bf = malloc(sizeof(BloomFilter));
    if (bf == NULL)
        goto error;
    memset(bf,0,sizeof(BloomFilter));
    bf->bitarray_size = size;
    bf->hash_iterations = iter;
    bf->Hash = Hash;

    /* setup the bitarray */
    bf->bitarray = malloc((bf->bitarray_size/8)+1);
    if (bf->bitarray == NULL)
        goto error;
    memset(bf->bitarray,0,(bf->bitarray_size/8)+1);

    return bf;

error:
    if (bf != NULL) {
        if (bf->bitarray != NULL)
            free(bf->bitarray);

        free(bf);
    }
    return NULL;
}

void BloomFilterFree(BloomFilter *bf) {
    if (bf != NULL) {
        if (bf->bitarray != NULL)
            free(bf->bitarray);

        free(bf);
    }
}

void BloomFilterPrint(BloomFilter *bf) {
    printf("\n---------- Bloom Filter Stats -----------\n");
    printf("Buckets:               %" PRIu32 "\n", bf->bitarray_size);
    printf("Memory size:           %" PRIu32 " bytes\n", bf->bitarray_size/8 + 1);
    printf("Hash function pointer: %p\n", bf->Hash);
    printf("Hash functions:        %" PRIu32 "\n", bf->hash_iterations);
    printf("-----------------------------------------\n");
}

int BloomFilterAdd(BloomFilter *bf, void *data, uint16_t datalen) {
    uint8_t iter = 0;
    uint32_t hash = 0;

    if (bf == NULL || data == NULL || datalen == 0)
        return -1;

    for (iter = 0; iter < bf->hash_iterations; iter++) {
        hash = bf->Hash(data, datalen, iter, bf->bitarray_size);
        bf->bitarray[hash/8] |= (1<<hash%8);
    }

    return 0;
}

inline int BloomFilterTest(BloomFilter *bf, void *data, uint16_t datalen) {
    uint8_t iter = 0;
    uint32_t hash = 0;
    int hit = 1;

    for (iter = 0; iter < bf->hash_iterations; iter++) {
        hash = bf->Hash(data, datalen, iter, bf->bitarray_size);
        if (!(bf->bitarray[hash/8] & (1<<hash%8))) {
            hit = 0;
            break;
        }
    }

    return hit;
}

uint32_t BloomFilterMemoryCnt(BloomFilter *bf) {
     if (bf == NULL)
         return 0;

     return 2;
}

uint32_t BloomFilterMemorySize(BloomFilter *bf) {
     if (bf == NULL)
         return 0;

     return (sizeof(BloomFilter) + (bf->bitarray_size/8) + 1);
}

static uint32_t BloomHash(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size) {
     uint8_t *d = (uint8_t *)data;
     uint32_t i;
     uint32_t hash = 0;

     for (i = 0; i < datalen; i++) {
         if (i == 0)      hash += (((uint32_t)*d++));
         else if (i == 1) hash += (((uint32_t)*d++) * datalen);
         else             hash *= (((uint32_t)*d++) * i);
     }

     hash *= (iter + datalen);
     hash %= hash_size;
     return hash;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
static int BloomFilterTestInit01 (void) {
    BloomFilter *bf = BloomFilterInit(1024, 4, BloomHash);
    if (bf == NULL)
        return 0;

    BloomFilterFree(bf);
    return 1;
}

/* no hash function, so it should fail */
static int BloomFilterTestInit02 (void) {
    BloomFilter *bf = BloomFilterInit(1024, 4, NULL);
    if (bf == NULL)
        return 1;

    BloomFilterFree(bf);
    return 0;
}

static int BloomFilterTestInit03 (void) {
    int result = 0;
    BloomFilter *bf = BloomFilterInit(1024, 4, BloomHash);
    if (bf == NULL)
        return 0;

    if (bf->Hash == BloomHash)
        result = 1;

    BloomFilterFree(bf);
    return result;
}

static int BloomFilterTestInit04 (void) {
    BloomFilter *bf = BloomFilterInit(1024, 0, BloomHash);
    if (bf == NULL)
        return 1;

    BloomFilterFree(bf);
    return 0;
}

static int BloomFilterTestInit05 (void) {
    BloomFilter *bf = BloomFilterInit(0, 4, BloomHash);
    if (bf == NULL)
        return 1;

    BloomFilterFree(bf);
    return 0;
}

static int BloomFilterTestAdd01 (void) {
    int result = 0;
    BloomFilter *bf = BloomFilterInit(1024, 4, BloomHash);
    if (bf == NULL)
        return 0;

    int r = BloomFilterAdd(bf, "test", 0);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterFree(bf);
    return result;
}

static int BloomFilterTestAdd02 (void) {
    int result = 0;
    BloomFilter *bf = BloomFilterInit(1024, 4, BloomHash);
    if (bf == NULL)
        return 0;

    int r = BloomFilterAdd(bf, NULL, 4);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterFree(bf);
    return result;
}

static int BloomFilterTestFull01 (void) {
    int result = 0;
    BloomFilter *bf = BloomFilterInit(32, 4, BloomHash);
    if (bf == NULL)
        goto end;

    int r = BloomFilterAdd(bf, "test", 4);
    if (r != 0)
        goto end;

    r = BloomFilterTest(bf, "test", 4);
    if (r != 1)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterFree(bf);
    return result;
}

static int BloomFilterTestFull02 (void) {
    int result = 0;
    BloomFilter *bf = BloomFilterInit(32, 4, BloomHash);
    if (bf == NULL)
        goto end;

    int r = BloomFilterTest(bf, "test", 4);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterFree(bf);
    return result;
}
#endif /* UNITTESTS */

void BloomFilterRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("BloomFilterTestInit01", BloomFilterTestInit01, 1);
    UtRegisterTest("BloomFilterTestInit02", BloomFilterTestInit02, 1);
    UtRegisterTest("BloomFilterTestInit03", BloomFilterTestInit03, 1);
    UtRegisterTest("BloomFilterTestInit04", BloomFilterTestInit04, 1);
    UtRegisterTest("BloomFilterTestInit05", BloomFilterTestInit05, 1);

    UtRegisterTest("BloomFilterTestAdd01", BloomFilterTestAdd01, 1);
    UtRegisterTest("BloomFilterTestAdd02", BloomFilterTestAdd02, 1);

    UtRegisterTest("BloomFilterTestFull01", BloomFilterTestFull01, 1);
    UtRegisterTest("BloomFilterTestFull02", BloomFilterTestFull02, 1);
#endif /* UNITTESTS */
}

