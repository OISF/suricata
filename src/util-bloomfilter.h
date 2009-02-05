/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __BLOOMFILTER_H__
#define __BLOOMFILTER_H__

/* Bloom Filter structure */
typedef struct _BloomFilter {
    u_int8_t *bitarray;
    u_int32_t bitarray_size;
    u_int8_t hash_iterations;
    u_int32_t (*Hash)(void *, u_int16_t, u_int8_t, u_int32_t);
} BloomFilter;

/* prototypes */
BloomFilter *BloomFilterInit(u_int32_t, u_int8_t, u_int32_t (*Hash)(void *, u_int16_t, u_int8_t, u_int32_t));
void BloomFilterFree(BloomFilter *);
void BloomFilterPrint(BloomFilter *);
int BloomFilterAdd(BloomFilter *, void *, u_int16_t);
int BloomFilterTest(BloomFilter *, void *, u_int16_t);
u_int32_t BloomFilterMemoryCnt(BloomFilter *);
u_int32_t BloomFilterMemorySize(BloomFilter *);

void BloomFilterRegisterTests(void);

#endif /* __BLOOMFILTER_H__ */

