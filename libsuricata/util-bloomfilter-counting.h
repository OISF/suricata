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

#ifndef __BLOOMFILTERCOUNTING_H__
#define __BLOOMFILTERCOUNTING_H__

/* Bloom filter structure */
typedef struct BloomFilterCounting_ {
    uint8_t *array;
    uint32_t array_size; /* size in buckets */
    uint8_t type; /* 1, 2 or 4 byte counters */
    uint8_t hash_iterations;
    uint32_t (*Hash)(const void *, uint16_t, uint8_t, uint32_t);
} BloomFilterCounting;

/* prototypes */
BloomFilterCounting *BloomFilterCountingInit(uint32_t, uint8_t, uint8_t, uint32_t (*Hash)(const void *, uint16_t, uint8_t, uint32_t));
void BloomFilterCountingFree(BloomFilterCounting *);
void BloomFilterCountingPrint(BloomFilterCounting *);
int BloomFilterCountingAdd(BloomFilterCounting *, const void *, uint16_t);
int BloomFilterCountingRemove(BloomFilterCounting *, const void *, uint16_t);
int BloomFilterCountingTest(BloomFilterCounting *, const void *, uint16_t);

void BloomFilterCountingRegisterTests(void);

#endif /* __BLOOMFILTERCOUNTING_H__ */

