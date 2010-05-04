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

#ifndef __HOST_H__
#define __HOST_H__

#include "decode.h"
#include "util-hash.h"
#include "util-bloomfilter-counting.h"

typedef struct HostTable_ {
    SCMutex m;

    /* storage & lookup */
    HashTable *hash;
    BloomFilterCounting *bf;

    uint32_t cnt;
} HostTable;

typedef struct Host_ {
    SCMutex m;

    Address addr;
    uint8_t os;
    uint8_t reputation;

    uint64_t bytes;
    uint32_t pkts;
} Host;

#define HOST_OS_UNKNOWN 0
/* XXX define more */

#define HOST_REPU_UNKNOWN 0
/* XXX see how we deal with this */

#endif /* __HOST_H__ */

