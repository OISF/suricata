/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef SURICATA_DATASETS_IPV4_H
#define SURICATA_DATASETS_IPV4_H

#include "datasets-reputation.h"
#include "datasets-context-json.h"

typedef struct IPv4Type {
    uint8_t ipv4[4];
    union {
        DataRepType rep;
        DataJsonType json;
    };
} IPv4Type;

int IPv4Set(void *dst, void *src);
int IPv4JsonSet(void *dst, void *src);
bool IPv4Compare(void *a, void *b);
uint32_t IPv4Hash(uint32_t hash_seed, void *s);
void IPv4Free(void *s);
void IPv4JsonFree(void *s);
uint32_t IPv4JsonGetLength(void *s);

#endif /* SURICATA_DATASETS_IPV4_H */
