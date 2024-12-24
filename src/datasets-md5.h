/* Copyright (C) 2017-2019 Open Information Security Foundation
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

#ifndef SURICATA_DATASETS_MD5_H
#define SURICATA_DATASETS_MD5_H

#include "datasets-reputation.h"

typedef struct Md5Type {
    uint8_t md5[16];
    DataRepType rep;
} Md5Type;

int Md5StrSet(void *dst, void *src);
bool Md5StrCompare(void *a, void *b);
uint32_t Md5StrHash(uint32_t hash_seed, void *s);
void Md5StrFree(void *s);

#endif /* SURICATA_DATASETS_MD5_H */
