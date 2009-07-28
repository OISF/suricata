/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __BLOOMFILTERCOUNTING_H__
#define __BLOOMFILTERCOUNTING_H__

/* Bloom filter structure */
typedef struct BloomFilterCounting_ {
    u_int8_t *array;
    u_int32_t array_size; /* size in buckets */
    u_int8_t type; /* 1, 2 or 4 byte counters */
    u_int8_t hash_iterations;
    u_int32_t (*Hash)(void *, u_int16_t, u_int8_t, u_int32_t);
} BloomFilterCounting;

/* prototypes */
BloomFilterCounting *BloomFilterCountingInit(u_int32_t, u_int8_t, u_int8_t, u_int32_t (*Hash)(void *, u_int16_t, u_int8_t, u_int32_t));
void BloomFilterCountingFree(BloomFilterCounting *);
void BloomFilterCountingPrint(BloomFilterCounting *);
int BloomFilterCountingAdd(BloomFilterCounting *, void *, u_int16_t);
int BloomFilterCountingRemove(BloomFilterCounting *, void *, u_int16_t);
int BloomFilterCountingTest(BloomFilterCounting *, void *, u_int16_t);

void BloomFilterCountingRegisterTests(void);

#endif /* __BLOOMFILTERCOUNTING_H__ */

