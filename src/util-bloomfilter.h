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
 */

#ifndef __BLOOMFILTER_H__
#define __BLOOMFILTER_H__

/* Bloom Filter structure */
typedef struct BloomFilter_ {
    uint8_t hash_iterations;
    uint32_t (*Hash)(const void *, uint16_t, uint8_t, uint32_t);
    uint32_t bitarray_size;
    uint8_t *bitarray;
} BloomFilter;

/* prototypes */
BloomFilter *BloomFilterInit(uint32_t, uint8_t, uint32_t (*Hash)(const void *, uint16_t, uint8_t, uint32_t));
void BloomFilterFree(BloomFilter *);
void BloomFilterPrint(BloomFilter *);
int BloomFilterAdd(BloomFilter *, const void *, uint16_t);
uint32_t BloomFilterMemoryCnt(BloomFilter *);
uint32_t BloomFilterMemorySize(BloomFilter *);

void BloomFilterRegisterTests(void);

/** ----- Inline functions ---- */

static inline int BloomFilterTest(const BloomFilter *, const void *, uint16_t);

static inline int BloomFilterTest(const BloomFilter *bf, const void *data, uint16_t datalen)
{
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

