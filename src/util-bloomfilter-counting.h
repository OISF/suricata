/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __BLOOMFILTERCOUNTING_H__
#define __BLOOMFILTERCOUNTING_H__

/* Bloom filter structure */
typedef struct BloomFilterCounting_ {
    uint8_t *array;
    uint32_t array_size; /* size in buckets */
    uint8_t type; /* 1, 2 or 4 byte counters */
    uint8_t hash_iterations;
    uint32_t (*Hash)(void *, uint16_t, uint8_t, uint32_t);
} BloomFilterCounting;

/* prototypes */
BloomFilterCounting *BloomFilterCountingInit(uint32_t, uint8_t, uint8_t, uint32_t (*Hash)(void *, uint16_t, uint8_t, uint32_t));
void BloomFilterCountingFree(BloomFilterCounting *);
void BloomFilterCountingPrint(BloomFilterCounting *);
int BloomFilterCountingAdd(BloomFilterCounting *, void *, uint16_t);
int BloomFilterCountingRemove(BloomFilterCounting *, void *, uint16_t);
int BloomFilterCountingTest(BloomFilterCounting *, void *, uint16_t);

void BloomFilterCountingRegisterTests(void);

#endif /* __BLOOMFILTERCOUNTING_H__ */

