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
inline int BloomFilterTest(BloomFilter *, void *, uint16_t);
uint32_t BloomFilterMemoryCnt(BloomFilter *);
uint32_t BloomFilterMemorySize(BloomFilter *);

void BloomFilterRegisterTests(void);

#endif /* __BLOOMFILTER_H__ */

