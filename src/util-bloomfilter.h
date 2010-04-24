/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __BLOOMFILTER_H__
#define __BLOOMFILTER_H__

/* Bloom Filter structure */
typedef struct BloomFilter_ {
    uint8_t *bitarray;
    uint32_t bitarray_size;
    uint8_t hash_iterations;
    uint32_t (*Hash)(void *, uint16_t, uint8_t, uint32_t);
} BloomFilter;

/* prototypes */
BloomFilter *BloomFilterInit(uint32_t, uint8_t, uint32_t (*Hash)(void *, uint16_t, uint8_t, uint32_t));
void BloomFilterFree(BloomFilter *);
void BloomFilterPrint(BloomFilter *);
int BloomFilterAdd(BloomFilter *, void *, uint16_t);
uint32_t BloomFilterMemoryCnt(BloomFilter *);
uint32_t BloomFilterMemorySize(BloomFilter *);

void BloomFilterRegisterTests(void);

/** ----- Inline functions ---- */

static inline int BloomFilterTest(BloomFilter *, void *, uint16_t);

static inline int BloomFilterTest(BloomFilter *bf, void *data, uint16_t datalen) {
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

#endif /* __BLOOMFILTER_H__ */

