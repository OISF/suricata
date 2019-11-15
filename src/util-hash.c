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

    if (hash >= ht->array_size) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "attempt to insert element out of hash array\n");
        goto error;
    }

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
    if (hb != NULL)
        SCFree(hb);
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

    if (hash >= ht->array_size) {
        SCLogWarning(SC_ERR_INVALID_VALUE, "attempt to access element out of hash array\n");
        return NULL;
    }

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


static const uint32_t crc32_table[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t HashFunctionCRC32(const uint8_t *buf, uint32_t len) {
    uint32_t crc = 0xFFFFFFFF;
    while (len--) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ *buf) & 0xFF];
        buf++;
    }
    return ~crc;
}

uint32_t HashFunctionMurmur(const uint8_t *buf, uint32_t len) {
    //IDS ICATA is a seed
    uint32_t h = 0x1D51CA7A;
    uint32_t k;
    uint32_t i=0;
    for (; i+3<len; i+=4) {
        k = *((uint32_t *) (buf + i));
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    if (i < len) {
        k = 0;
        uint8_t incomplete[4];
        for (; i<len; i++) {
            incomplete[i%4] = buf[i];
        }
        k = *((uint32_t *) (incomplete));
        k *= 0xcc9e2d51;
        k = (k << 15) | (k >> 17);
        k *= 0x1b873593;
        h ^= k;
    }
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

uint32_t HashFunctionDjb2(const uint8_t *buf, uint32_t len) {
    uint32_t hash = 5381;
    for (uint32_t i=0; i<len; i++) {
        hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */
    }
    return hash;
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

    int r = HashTableAdd(ht, (char *)"test", 0);
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

    int r = HashTableAdd(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    char *rp = HashTableLookup(ht, (char *)"test", 4);
    if (rp == NULL)
        goto end;

    r = HashTableRemove(ht, (char *)"test", 4);
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

    int r = HashTableAdd(ht, (char *)"test", 4);
    if (r != 0)
        goto end;

    char *rp = HashTableLookup(ht, (char *)"test", 4);
    if (rp == NULL)
        goto end;

    r = HashTableRemove(ht, (char *)"test2", 5);
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
    UtRegisterTest("HashTableTestInit01", HashTableTestInit01);
    UtRegisterTest("HashTableTestInit02", HashTableTestInit02);
    UtRegisterTest("HashTableTestInit03", HashTableTestInit03);
    UtRegisterTest("HashTableTestInit04", HashTableTestInit04);
    UtRegisterTest("HashTableTestInit05", HashTableTestInit05);
    UtRegisterTest("HashTableTestInit06", HashTableTestInit06);

    UtRegisterTest("HashTableTestAdd01", HashTableTestAdd01);
    UtRegisterTest("HashTableTestAdd02", HashTableTestAdd02);

    UtRegisterTest("HashTableTestFull01", HashTableTestFull01);
    UtRegisterTest("HashTableTestFull02", HashTableTestFull02);
#endif
}

