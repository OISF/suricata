/* Copyright (C) 2025 Open Information Security Foundation
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
 *
 * Structure to handle packet flood.
 *
 */

#ifndef SURICATA_UTIL_FLOOD_H
#define SURICATA_UTIL_FLOOD_H

#include "util-hash.h"
#include "decode.h"
#include "flow.h"

enum {
    FSR_USED = BIT_U8(0),
    FSR_SYN = BIT_U8(1),
    FSR_OTHERS = BIT_U8(2),
};

typedef struct FloodStorageRingElt_ {
    Packet *p;
    uint64_t pkts_cnt;
    uint64_t bytes_cnt;
    uint8_t flags;
} FloodStorageRingElt;

typedef struct FloodStorage_ {
    HashTable *new_hash;
    HashTable *est_hash;
    FloodStorageRingElt *new_ring;
    FloodStorageRingElt *new_ins;
    size_t size;
    uint16_t stored;
    uint16_t passed;
    uint16_t dropped;
    uint16_t est_hit;
    uint16_t est_nohit;
    uint16_t one_way_pkts;
    uint16_t one_way_bytes;
    uint16_t one_way_flows;
    uint16_t syn_pkts;
    uint16_t syn_bytes;
} FloodStorage;

FloodStorage *FloodStorageInit(ThreadVars *tv, size_t size);
void FloodStorageDeinit(ThreadVars *tv, FloodStorage *fst);
Packet *FloodStorageNewCheck(ThreadVars *tv, FloodStorage *fst, Packet *p);
bool FloodStorageIsEstablished(ThreadVars *tv, FloodStorage *fst, Packet *p);
void FloodStorageRemovedEstablished(ThreadVars *tv, FloodStorage *fst, Flow *f);

#endif /* SURICATA_UTIL_FLOOD_H */
