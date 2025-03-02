/* Copyright (C) 2024 Open Information Security Foundation
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

#ifndef SURICATA_DATAJSON_SHA56_H
#define SURICATA_DATAJSON_SHA56_H

typedef struct Sha256TypeJson {
    uint8_t sha256[32];
    DataJsonType json;
} Sha256TypeJson;

int Sha256StrJsonSet(void *dst, void *src);
bool Sha256StrJsonCompare(void *a, void *b);
uint32_t Sha256StrJsonHash(uint32_t hash_seed, void *s);
void Sha256StrJsonFree(void *s);

#endif
