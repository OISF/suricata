/* Copyright (C) 2017-2022 Open Information Security Foundation
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

#ifndef __DATASETS_SHA256_H__
#define __DATASETS_SHA256_H__

#include "datasets-reputation.h"

typedef struct Sha256Type {
    uint8_t sha256[32];
    DataRepType rep;
} Sha256Type;

int Sha256StrSet(void *dst, void *src);
bool Sha256StrCompare(void *a, void *b);
uint32_t Sha256StrHash(void *s);
void Sha256StrFree(void *s);

#endif /* __DATASETS_SHA256_H__ */
