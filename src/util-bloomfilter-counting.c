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
 * Counting Bloom Filter implementation. Can be used with 8, 16, 32 bits
 * counters.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#endif
#include "util-bloomfilter-counting.h"

/* type: 1, 2 or 4 for 8, 16, or 32 bit counters
 *
 */
BloomFilterCounting *BloomFilterCountingInit(uint32_t size, uint8_t type, uint8_t iter, uint32_t (*Hash)(const void *, uint16_t, uint8_t, uint32_t)) {
    BloomFilterCounting *bf = NULL;

    if (iter == 0)
        goto error;

    if (Hash == NULL || size == 0) {
        //printf("ERROR: BloomFilterCountingInit no Hash function\n");
        goto error;
    }

    if (type != 1 && type != 2 && type != 4) {
        //printf("ERROR: BloomFilterCountingInit only 1, 2 and 4 bytes are supported\n");
        goto error;
    }

    /* setup the filter */
    bf = SCMalloc(sizeof(BloomFilterCounting));
    if (unlikely(bf == NULL))
        goto error;
    memset(bf,0,sizeof(BloomFilterCounting));
    bf->type = type; /* size of the type: 1, 2, 4 */
    bf->array_size = size;
    bf->hash_iterations = iter;
    bf->Hash = Hash;

    /* setup the bitarray */
    bf->array = SCMalloc(bf->array_size * bf->type);
    if (bf->array == NULL)
        goto error;
    memset(bf->array,0,bf->array_size * bf->type);

    return bf;

error:
    if (bf != NULL) {
        if (bf->array != NULL)
            SCFree(bf->array);

        SCFree(bf);
    }
    return NULL;
}

void BloomFilterCountingFree(BloomFilterCounting *bf)
{
    if (bf != NULL) {
        if (bf->array != NULL)
            SCFree(bf->array);

        SCFree(bf);
    }
}

void BloomFilterCountingPrint(BloomFilterCounting *bf)
{
    printf("\n------ Counting Bloom Filter Stats ------\n");
    printf("Buckets:               %" PRIu32 "\n", bf->array_size);
    printf("Counter size:          %" PRIu32 "\n", bf->type);
    printf("Memory size:           %" PRIu32 " bytes\n", bf->array_size * bf->type);
    printf("Hash function pointer: %p\n", bf->Hash);
    printf("Hash functions:        %" PRIu32 "\n", bf->hash_iterations);
    printf("-----------------------------------------\n");
}

int BloomFilterCountingAdd(BloomFilterCounting *bf, const void *data, uint16_t datalen)
{
    uint8_t iter = 0;
    uint32_t hash = 0;

    if (bf == NULL || data == NULL || datalen == 0)
        return -1;

    for (iter = 0; iter < bf->hash_iterations; iter++) {
        hash = bf->Hash(data, datalen, iter, bf->array_size) * bf->type;
        if (bf->type == 1) {
            uint8_t *u8 = (uint8_t *)&bf->array[hash];
            if ((*u8) != 255)
                (*u8)++;
        } else if (bf->type == 2) {
            uint16_t *u16 = (uint16_t *)&bf->array[hash];
            if ((*u16) != 65535)
                (*u16)++;
        } else if (bf->type == 4) {
            uint32_t *u32 = (uint32_t *)&bf->array[hash];
            if ((*u32) != 4294967295UL)
                (*u32)++;
        }
    }

    return 0;
}

int BloomFilterCountingRemove(BloomFilterCounting *bf, const void *data, uint16_t datalen)
{
    uint8_t iter = 0;
    uint32_t hash = 0;

    if (bf == NULL || data == NULL || datalen == 0)
        return -1;

    /* only remove data that was actually added */
    if (BloomFilterCountingTest(bf, data, datalen) == 0) {
        printf("ERROR: BloomFilterCountingRemove tried to remove data "
               "that was never added to the set or was already removed.\n");
        return -1;
    }

    /* decrease counters for every iteration */
    for (iter = 0; iter < bf->hash_iterations; iter++) {
        hash = bf->Hash(data, datalen, iter, bf->array_size) * bf->type;
        if (bf->type == 1) {
            uint8_t *u8 = (uint8_t *)&bf->array[hash];
            if ((*u8) > 0)
                (*u8)--;
            else {
                printf("ERROR: BloomFilterCountingRemove tried to decrease a "
                       "counter below zero.\n");
                return -1;
            }
        } else if (bf->type == 2) {
            uint16_t *u16 = (uint16_t *)&bf->array[hash];
            if ((*u16) > 0)
                (*u16)--;
            else {
                printf("ERROR: BloomFilterCountingRemove tried to decrease a "
                       "counter below zero.\n");
                return -1;
            }
        } else if (bf->type == 4) {
            uint32_t *u32 = (uint32_t *)&bf->array[hash];
            if ((*u32) > 0)
                (*u32)--;
            else {
                printf("ERROR: BloomFilterCountingRemove tried to decrease a "
                       "counter below zero.\n");
                return -1;
            }
        }
    }

    return 0;
}

/* Test if data matches our filter and is likely to be in the set
 *
 * returns 0: for no match
 *         1: match
 */
int BloomFilterCountingTest(BloomFilterCounting *bf, const void *data, uint16_t datalen)
{
    uint8_t iter = 0;
    uint32_t hash = 0;
    int hit = 1;

    /* check each hash iteration */
    for (iter = 0; iter < bf->hash_iterations; iter++) {
        hash = bf->Hash(data, datalen, iter, bf->array_size) * bf->type;
        if (bf->type == 1) {
            uint8_t *u8 = (uint8_t *)&bf->array[hash];
            if ((*u8) == 0x00) {
                hit = 0;
                break;
            }
        } else if (bf->type == 2) {
            uint16_t *u16 = (uint16_t *)&bf->array[hash];
            if ((*u16) == 0x0000) {
                hit = 0;
                break;
            }
        } else if (bf->type == 4) {
            uint32_t *u32 = (uint32_t *)&bf->array[hash];
            if ((*u32) == 0x00000000) {
                hit = 0;
                break;
            }
        }
    }

    return hit;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
static uint32_t BloomHash(const void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size)
{
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

static int BloomFilterCountingTestInit01 (void)
{
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 4, 4, BloomHash);
    if (bf == NULL)
        return 0;

    BloomFilterCountingFree(bf);
    return 1;
}

/* no hash function, so it should fail */
static int BloomFilterCountingTestInit02 (void)
{
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 4, 4, NULL);
    if (bf == NULL)
        return 1;

    BloomFilterCountingFree(bf);
    return 0;
}

static int BloomFilterCountingTestInit03 (void)
{
    int result = 0;
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 4, 4, BloomHash);
    if (bf == NULL)
        return 0;

    if (bf->Hash == BloomHash)
        result = 1;

    BloomFilterCountingFree(bf);
    return result;
}

static int BloomFilterCountingTestInit04 (void)
{
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 0, 4, BloomHash);
    if (bf == NULL)
        return 1;

    BloomFilterCountingFree(bf);
    return 0;
}

static int BloomFilterCountingTestInit05 (void)
{
    BloomFilterCounting *bf = BloomFilterCountingInit(0, 4, 4, BloomHash);
    if (bf == NULL)
        return 1;

    BloomFilterCountingFree(bf);
    return 0;
}

static int BloomFilterCountingTestInit06 (void)
{
    BloomFilterCounting *bf = BloomFilterCountingInit(32, 3, 4, BloomHash);
    if (bf == NULL)
        return 1;

    BloomFilterCountingFree(bf);
    return 0;
}

static int BloomFilterCountingTestAdd01 (void)
{
    int result = 0;
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 4, 4, BloomHash);
    if (bf == NULL)
        return 0;

    int r = BloomFilterCountingAdd(bf, "test", 0);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterCountingFree(bf);
    return result;
}

static int BloomFilterCountingTestAdd02 (void)
{
    int result = 0;
    BloomFilterCounting *bf = BloomFilterCountingInit(1024, 4, 4, BloomHash);
    if (bf == NULL)
        return 0;

    int r = BloomFilterCountingAdd(bf, NULL, 4);
    if (r == 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterCountingFree(bf);
    return result;
}

static int BloomFilterCountingTestFull01 (void)
{
    int result = 0;
    BloomFilterCounting *bf = BloomFilterCountingInit(32, 4, 4, BloomHash);
    if (bf == NULL) {
        printf("init failed: ");
        goto end;
    }

    int r = BloomFilterCountingAdd(bf, "test", 4);
    if (r != 0) {
        printf("first add: ");
        goto end;
    }

    r = BloomFilterCountingTest(bf, "test", 4);
    if (r != 1) {
        printf("2nd add: ");
        goto end;
    }

    r = BloomFilterCountingRemove(bf, "test", 4);
    if (r != 0) {
        printf("3rd add: ");
        goto end;
    }

    /* all is good! */
    result = 1;
end:
    if (bf != NULL)
        BloomFilterCountingFree(bf);
    return result;
}

static int BloomFilterCountingTestFull02 (void)
{
    int result = 0;
    BloomFilterCounting *bf = BloomFilterCountingInit(32, 4, 4, BloomHash);
    if (bf == NULL)
        goto end;

    int r = BloomFilterCountingTest(bf, "test", 4);
    if (r != 0)
        goto end;

    /* all is good! */
    result = 1;
end:
    if (bf != NULL) BloomFilterCountingFree(bf);
    return result;
}
#endif

void BloomFilterCountingRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("BloomFilterCountingTestInit01",
                   BloomFilterCountingTestInit01);
    UtRegisterTest("BloomFilterCountingTestInit02",
                   BloomFilterCountingTestInit02);
    UtRegisterTest("BloomFilterCountingTestInit03",
                   BloomFilterCountingTestInit03);
    UtRegisterTest("BloomFilterCountingTestInit04",
                   BloomFilterCountingTestInit04);
    UtRegisterTest("BloomFilterCountingTestInit05",
                   BloomFilterCountingTestInit05);
    UtRegisterTest("BloomFilterCountingTestInit06",
                   BloomFilterCountingTestInit06);

    UtRegisterTest("BloomFilterCountingTestAdd01",
                   BloomFilterCountingTestAdd01);
    UtRegisterTest("BloomFilterCountingTestAdd02",
                   BloomFilterCountingTestAdd02);

    UtRegisterTest("BloomFilterCountingTestFull01",
                   BloomFilterCountingTestFull01);
    UtRegisterTest("BloomFilterCountingTestFull02",
                   BloomFilterCountingTestFull02);
#endif
}

