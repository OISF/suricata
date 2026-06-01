/* Copyright (C) 2026 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 */

#ifndef SURICATA_DATASETS_CIDR_H
#define SURICATA_DATASETS_CIDR_H

#include "datasets.h"
#include "util-radix4-tree.h"
#include "util-radix6-tree.h"
#include "threads.h"

typedef struct CIDRIPv4Type {
    SCRadix4Tree tree;
    SCRWLock lock;
    /* Approximate bytes consumed by stored entries, for memcap.
     * Atomic so future stats consumers can sample without contending the lock. */
    SC_ATOMIC_DECLARE(uint64_t, bytes);
    /* Cumulative count of new-entry inserts rejected because memcap was
     * reached. Used to re-emit a periodic WARNING so operators see
     * continued pressure instead of just the first-hit warning. */
    SC_ATOMIC_DECLARE(uint64_t, rejected);
    uint64_t memcap; /* 0 = unlimited; set at CIDRNew, immutable after */
} CIDRIPv4Type;

typedef struct CIDRIPv6Type {
    SCRadix6Tree tree;
    SCRWLock lock;
    SC_ATOMIC_DECLARE(uint64_t, bytes);
    SC_ATOMIC_DECLARE(uint64_t, rejected);
    uint64_t memcap;
} CIDRIPv6Type;

typedef struct CIDRType {
    CIDRIPv4Type ipv4;
    CIDRIPv6Type ipv6;
} CIDRType;

/* Per-entry byte estimate used to check memcap. Node size varies with
 * tree topology (internal vs leaf nodes, alignment), and internal split
 * nodes are not counted here, so real memory use is higher than the
 * tracked total. Treat these as approximate. */
#define CIDR_IPV4_ENTRY_BYTES 128
#define CIDR_IPV6_ENTRY_BYTES 192

CIDRType *CIDRNew(uint64_t memcap);
void CIDRFree(CIDRType *cidr);
void CIDRClear(CIDRType *cidr);

/* Raw-byte add helpers. Enforce the memcap configured at CIDRNew time.
 * Return 1 if a new entry was added, 0 if it was already present,
 * -1 on parameter error, -2 on memcap exhaustion. */
int CIDRAddIPv4Netblock(
        CIDRIPv4Type *ipv4, const char *set_name, const uint8_t *addr, uint8_t prefix);
int CIDRAddIPv6Netblock(
        CIDRIPv6Type *ipv6, const char *set_name, const uint8_t *addr, uint8_t prefix);

bool CIDRLookupIPv4(CIDRIPv4Type *ipv4, const uint8_t *addr);
bool CIDRLookupIPv6(CIDRIPv6Type *ipv6, const uint8_t *addr);
bool CIDRRemoveIPv4Netblock(CIDRIPv4Type *ipv4, const uint8_t *addr, uint8_t prefix);
bool CIDRRemoveIPv6Netblock(CIDRIPv6Type *ipv6, const uint8_t *addr, uint8_t prefix);

int DatasetAddCIDRString(Dataset *set, const char *cidr_str);
int DatasetRemoveCIDRString(Dataset *set, const char *cidr_str);
int DatasetLookupCIDRString(Dataset *set, const char *cidr_str);

#endif /* SURICATA_DATASETS_CIDR_H */
