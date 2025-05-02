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

#ifndef SURICATA_DATASETS_SHA256_H
#define SURICATA_DATASETS_SHA256_H

#include "datasets-reputation.h"
#include "datasets-context-json.h"

typedef struct Sha256Type {
    uint8_t sha256[32];
    union {
        DataRepType rep;
        DataJsonType json;
    };
} Sha256Type;

int Sha256StrSet(void *dst, void *src);
int Sha256StrJsonSet(void *dst, void *src);
bool Sha256StrCompare(void *a, void *b);
uint32_t Sha256StrHash(uint32_t hash_seed, void *s);
void Sha256StrFree(void *s);
void Sha256StrJsonFree(void *s);
uint32_t Sha256StrJsonGetLength(void *s);

#endif /* SURICATA_DATASETS_SHA256_H */
