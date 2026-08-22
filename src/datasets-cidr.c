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

#include "suricata-common.h"
#include "datasets-cidr.h"
#include "util-ip.h"

/* Radix tree configs: no user-data free callback, no debug print callback. */
static SCRadix4Config radix4_cfg = { 0 };
static SCRadix6Config radix6_cfg = { 0 };

/**
 * \internal
 * \brief Reserve one entry against a per-family memcap.
 *
 * Called while the family write lock is held. Bumps `bytes` on success.
 * On memcap exhaustion, bumps `rejected` and emits a WARNING on the
 * first rejection and again every million rejections, so operators
 * see continued pressure rather than a single lost initial warning.
 *
 * \retval 0 reservation ok; caller should insert
 * \retval -2 memcap exhausted; caller should reject with SC_ENOENT-equivalent
 */
static inline int cidr_reserve_entry(_Atomic(uint64_t) * bytes, _Atomic(uint64_t) * rejected,
        uint64_t memcap, uint64_t entry_bytes, const char *set_name, const char *family_str)
{
    if (memcap != 0) {
        uint64_t cur = atomic_load(bytes);
        /* Written as "entry_bytes > memcap - cur" to avoid wrapping when
         * memcap is close to UINT64_MAX. cur <= memcap holds because we
         * only enter this branch after prior successful reserves. */
        if (cur > memcap || entry_bytes > memcap - cur) {
            uint64_t r = atomic_fetch_add(rejected, 1) + 1;
            if (r == 1 || (r % 1000000) == 0) {
                SCLogWarning("CIDR dataset '%s' memcap reached (%s); rejected %" PRIu64
                             " new-entry insert(s) so far",
                        set_name ? set_name : "(unknown)", family_str, r);
            }
            return -2;
        }
    }
    atomic_fetch_add(bytes, entry_bytes);
    return 0;
}

/**
 * \internal
 * \brief Release one entry's byte accounting (opposite of cidr_reserve_entry).
 */
static inline void cidr_release_entry(_Atomic(uint64_t) * bytes, uint64_t entry_bytes)
{
    uint64_t cur = atomic_load(bytes);
    if (cur >= entry_bytes)
        atomic_fetch_sub(bytes, entry_bytes);
}

/**
 * \brief Parse a CIDR notation string into a binary address and prefix length.
 *        Does not log on failure -- the caller reports one error after trying
 *        both address families.
 * \param cidr_str Input string, e.g. "192.168.1.0/24" or "2001:db8::/32"
 * \param af Address family: AF_INET or AF_INET6
 * \param addr_out Receives the parsed address bytes
 * \param mask_out Receives the prefix length
 * \param max_mask Maximum valid prefix length (32 for IPv4, 128 for IPv6)
 * \retval 0 on success
 * \retval -1 on parse error
 */
static int ParseCIDRString(
        const char *cidr_str, int af, void *addr_out, int *mask_out, int max_mask)
{
    char ip_copy[256];
    if (strlcpy(ip_copy, cidr_str, sizeof(ip_copy)) >= sizeof(ip_copy))
        return -1;

    int mask = max_mask;
    char *slash = strchr(ip_copy, '/');
    if (slash != NULL) {
        *slash = '\0';
        const char *prefix_str = slash + 1;
        if (*prefix_str == '\0' || *prefix_str == '-')
            return -1;
        char *endptr = NULL;
        errno = 0;
        long m = strtol(prefix_str, &endptr, 10);
        if (errno != 0 || endptr == prefix_str || *endptr != '\0' || m < 0 || m > max_mask)
            return -1;
        mask = (int)m;
    }

    if (inet_pton(af, ip_copy, addr_out) != 1)
        return -1;

    *mask_out = mask;
    return 0;
}

/**
 * \brief Parse a CIDR string and dispatch by address family.
 * \retval 1 = IPv4, 2 = IPv6, -1 = parse failed
 * On success, exactly one of v4/mask4 or v6/mask6 is populated.
 */
static int ParseCIDRAny(const char *cidr_str, struct in_addr *v4, int *mask4, struct in6_addr *v6,
        int *mask6)
{
    if (ParseCIDRString(cidr_str, AF_INET, v4, mask4, 32) == 0)
        return 1;
    if (ParseCIDRString(cidr_str, AF_INET6, v6, mask6, 128) == 0)
        return 2;
    return -1;
}

/**
 * \brief Retrieve the CIDRType from a Dataset, validating type and initialization
 * \param set The dataset
 * \retval CIDRType* on success
 * \retval NULL if set is NULL, wrong type, or uninitialized
 */
static inline CIDRType *CIDRFromDataset(const Dataset *set)
{
    if (set == NULL || set->type != DATASET_TYPE_CIDR || set->cidr_data == NULL)
        return NULL;
    return set->cidr_data;
}

CIDRType *CIDRNew(uint64_t memcap)
{
    CIDRType *cidr = SCCalloc(1, sizeof(*cidr));
    if (cidr == NULL)
        return NULL;
    cidr->ipv4.tree = SCRadix4TreeInitialize();
    cidr->ipv4.memcap = memcap;
    SC_ATOMIC_INIT(cidr->ipv4.bytes);
    SC_ATOMIC_INIT(cidr->ipv4.rejected);
    SCRWLockInit(&cidr->ipv4.lock, NULL);
    cidr->ipv6.tree = SCRadix6TreeInitialize();
    cidr->ipv6.memcap = memcap;
    SC_ATOMIC_INIT(cidr->ipv6.bytes);
    SC_ATOMIC_INIT(cidr->ipv6.rejected);
    SCRWLockInit(&cidr->ipv6.lock, NULL);
    return cidr;
}

void CIDRFree(CIDRType *cidr)
{
    if (cidr == NULL)
        return;
    SCRadix4TreeRelease(&cidr->ipv4.tree, &radix4_cfg);
    SCRWLockDestroy(&cidr->ipv4.lock);
    SCRadix6TreeRelease(&cidr->ipv6.tree, &radix6_cfg);
    SCRWLockDestroy(&cidr->ipv6.lock);
    SCFree(cidr);
}

void CIDRClear(CIDRType *cidr)
{
    if (cidr == NULL)
        return;
    /* Hold both write locks for the whole operation so an observer never
     * sees "one family empty, the other full". Order ipv4-before-ipv6 is
     * fixed to avoid any future deadlock if another path ever takes both. */
    SCRWLockWRLock(&cidr->ipv4.lock);
    SCRWLockWRLock(&cidr->ipv6.lock);

    SCRadix4TreeRelease(&cidr->ipv4.tree, &radix4_cfg);
    cidr->ipv4.tree = SCRadix4TreeInitialize();
    SC_ATOMIC_SET(cidr->ipv4.bytes, 0);
    SC_ATOMIC_SET(cidr->ipv4.rejected, 0);

    SCRadix6TreeRelease(&cidr->ipv6.tree, &radix6_cfg);
    cidr->ipv6.tree = SCRadix6TreeInitialize();
    SC_ATOMIC_SET(cidr->ipv6.bytes, 0);
    SC_ATOMIC_SET(cidr->ipv6.rejected, 0);

    SCRWLockUnlock(&cidr->ipv6.lock);
    SCRWLockUnlock(&cidr->ipv4.lock);
}

/**
 * \brief Add a raw-byte IPv4 network entry, enforcing the tree's memcap.
 * \param ipv4 The IPv4 tree wrapper (memcap read from ipv4->memcap)
 * \param set_name Dataset name for the memcap warning log
 * \param addr 4-byte IPv4 address (host bits may be set; will be masked)
 * \param prefix Prefix length (0..32; 32 = host route)
 * \retval 1 if a new entry was inserted
 * \retval 0 if the entry was already present
 * \retval -1 on parameter error
 * \retval -2 on memcap exhaustion
 */
int CIDRAddIPv4Netblock(
        CIDRIPv4Type *ipv4, const char *set_name, const uint8_t *addr, uint8_t prefix)
{
    if (ipv4 == NULL || addr == NULL || prefix == 0 || prefix > 32)
        return -1;

    uint8_t masked[4];
    memcpy(masked, addr, 4);
    if (prefix < 32)
        MaskIPNetblock(masked, prefix, 32);

    /* Fast path: read-locked probe. Under a spoofed-source flood most
     * arrivals re-hit an entry already in the tree; serving those without
     * touching the write lock lets readers scale across cores. */
    SCRWLockRDLock(&ipv4->lock);
    void *user_data = NULL;
    SCRadix4Node *existing = SCRadix4TreeFindNetblock(&ipv4->tree, masked, prefix, &user_data);
    SCRWLockUnlock(&ipv4->lock);
    if (existing != NULL)
        return 0;

    /* Slow path: writer contention. Re-check under the write lock in case
     * a concurrent writer inserted the same entry between our probe and
     * the wrlock. */
    SCRWLockWRLock(&ipv4->lock);
    existing = SCRadix4TreeFindNetblock(&ipv4->tree, masked, prefix, &user_data);
    int rc;
    if (existing != NULL) {
        rc = 0;
    } else if (cidr_reserve_entry(&ipv4->bytes_sc_atomic__, &ipv4->rejected_sc_atomic__,
                       ipv4->memcap, CIDR_IPV4_ENTRY_BYTES, set_name, "IPv4") != 0) {
        rc = -2;
    } else if (SCRadix4AddKeyIPV4Netblock(&ipv4->tree, &radix4_cfg, masked, prefix, NULL) ==
               NULL) {
        cidr_release_entry(&ipv4->bytes_sc_atomic__, CIDR_IPV4_ENTRY_BYTES);
        rc = -1;
    } else {
        rc = 1;
    }
    SCRWLockUnlock(&ipv4->lock);
    return rc;
}

/**
 * \brief Add a raw-byte IPv6 network entry, enforcing the tree's memcap.
 * \param ipv6 The IPv6 tree wrapper (memcap read from ipv6->memcap)
 * \param set_name Dataset name for the memcap warning log
 * \param addr 16-byte IPv6 address (host bits may be set; will be masked)
 * \param prefix Prefix length (0..128; 128 = host route)
 * \retval 1 if a new entry was inserted
 * \retval 0 if the entry was already present
 * \retval -1 on parameter error
 * \retval -2 on memcap exhaustion
 */
int CIDRAddIPv6Netblock(
        CIDRIPv6Type *ipv6, const char *set_name, const uint8_t *addr, uint8_t prefix)
{
    if (ipv6 == NULL || addr == NULL || prefix == 0 || prefix > 128)
        return -1;

    uint8_t masked[16];
    memcpy(masked, addr, 16);
    if (prefix < 128)
        MaskIPNetblock(masked, prefix, 128);

    SCRWLockRDLock(&ipv6->lock);
    void *user_data = NULL;
    SCRadix6Node *existing = SCRadix6TreeFindNetblock(&ipv6->tree, masked, prefix, &user_data);
    SCRWLockUnlock(&ipv6->lock);
    if (existing != NULL)
        return 0;

    SCRWLockWRLock(&ipv6->lock);
    existing = SCRadix6TreeFindNetblock(&ipv6->tree, masked, prefix, &user_data);
    int rc;
    if (existing != NULL) {
        rc = 0;
    } else if (cidr_reserve_entry(&ipv6->bytes_sc_atomic__, &ipv6->rejected_sc_atomic__,
                       ipv6->memcap, CIDR_IPV6_ENTRY_BYTES, set_name, "IPv6") != 0) {
        rc = -2;
    } else if (SCRadix6AddKeyIPV6Netblock(&ipv6->tree, &radix6_cfg, masked, prefix, NULL) ==
               NULL) {
        cidr_release_entry(&ipv6->bytes_sc_atomic__, CIDR_IPV6_ENTRY_BYTES);
        rc = -1;
    } else {
        rc = 1;
    }
    SCRWLockUnlock(&ipv6->lock);
    return rc;
}

/**
 * \brief Check if an IPv4 address falls within any CIDR in the tree
 * \param ipv4 The IPv4 tree node
 * \param addr IPv4 address (4 bytes)
 * \retval true if address is covered by a stored prefix
 */
bool CIDRLookupIPv4(CIDRIPv4Type *ipv4, const uint8_t *addr)
{
    if (ipv4 == NULL || addr == NULL)
        return false;

    SCRWLockRDLock(&ipv4->lock);
    void *user_data = NULL; /* required by API, unused */
    SCRadix4Node *node = SCRadix4TreeFindBestMatch(&ipv4->tree, addr, &user_data);
    bool found = (node != NULL);
    SCRWLockUnlock(&ipv4->lock);
    return found;
}

/**
 * \brief Check if an IPv6 address falls within any CIDR in the tree
 * \param ipv6 The IPv6 tree node
 * \param addr IPv6 address (16 bytes)
 * \retval true if address is covered by a stored prefix
 */
bool CIDRLookupIPv6(CIDRIPv6Type *ipv6, const uint8_t *addr)
{
    if (ipv6 == NULL || addr == NULL)
        return false;

    SCRWLockRDLock(&ipv6->lock);
    void *user_data = NULL; /* required by API, unused */
    SCRadix6Node *node = SCRadix6TreeFindBestMatch(&ipv6->tree, addr, &user_data);
    bool found = (node != NULL);
    SCRWLockUnlock(&ipv6->lock);
    return found;
}

/**
 * \brief Remove an exact netblock IPv4 entry if present, under a single write lock
 * \param ipv4 The IPv4 tree node
 * \param addr IPv4 address (4 bytes)
 * \param prefix Prefix length (1-32)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv4Netblock(CIDRIPv4Type *ipv4, const uint8_t *addr, uint8_t prefix)
{
    if (ipv4 == NULL || addr == NULL)
        return false;

    /* The tree stores masked network addresses; mask the query address to match. */
    uint8_t masked[4];
    memcpy(masked, addr, 4);
    if (prefix < 32)
        MaskIPNetblock(masked, prefix, 32);

    /* Remove is admin/rule-driven, not per-packet, so it does not use the
     * rdlock-first probe that Add uses. Go straight to the write lock. */
    SCRWLockWRLock(&ipv4->lock);
    void *user_data = NULL;
    SCRadix4Node *node = SCRadix4TreeFindNetblock(&ipv4->tree, masked, prefix, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix4RemoveKeyIPV4Netblock(&ipv4->tree, &radix4_cfg, masked, prefix);
        cidr_release_entry(&ipv4->bytes_sc_atomic__, CIDR_IPV4_ENTRY_BYTES);
    }
    SCRWLockUnlock(&ipv4->lock);
    return found;
}

/**
 * \brief Remove an exact netblock IPv6 entry if present, under a single write lock
 * \param ipv6 The IPv6 tree node
 * \param addr IPv6 address (16 bytes)
 * \param prefix Prefix length (1-128)
 * \retval true if the entry was found and removed
 * \retval false if the entry was not present
 */
bool CIDRRemoveIPv6Netblock(CIDRIPv6Type *ipv6, const uint8_t *addr, uint8_t prefix)
{
    if (ipv6 == NULL || addr == NULL)
        return false;

    /* The tree stores masked network addresses; mask the query address to match. */
    uint8_t masked[16];
    memcpy(masked, addr, 16);
    if (prefix < 128)
        MaskIPNetblock(masked, prefix, 128);

    /* See CIDRRemoveIPv4Netblock for why there's no rdlock probe here. */
    SCRWLockWRLock(&ipv6->lock);
    void *user_data = NULL;
    SCRadix6Node *node = SCRadix6TreeFindNetblock(&ipv6->tree, masked, prefix, &user_data);
    bool found = (node != NULL);
    if (found) {
        SCRadix6RemoveKeyIPV6Netblock(&ipv6->tree, &radix6_cfg, masked, prefix);
        cidr_release_entry(&ipv6->bytes_sc_atomic__, CIDR_IPV6_ENTRY_BYTES);
    }
    SCRWLockUnlock(&ipv6->lock);
    return found;
}

/**
 * \brief Add a CIDR string to a dataset
 * \param set The dataset
 * \param cidr_str CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * \retval 1 on success (added or already present)
 * \retval -1 on error
 */
int DatasetAddCIDRString(Dataset *set, const char *cidr_str)
{
    if (cidr_str == NULL)
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr v4;
    struct in6_addr v6;
    int mask4 = 0, mask6 = 0;
    int r;
    switch (ParseCIDRAny(cidr_str, &v4, &mask4, &v6, &mask6)) {
        case 1:
            r = CIDRAddIPv4Netblock(
                    &cidr->ipv4, set->name, (const uint8_t *)&v4.s_addr, (uint8_t)mask4);
            return r >= 0 ? r : -1;
        case 2:
            r = CIDRAddIPv6Netblock(
                    &cidr->ipv6, set->name, (const uint8_t *)&v6.s6_addr, (uint8_t)mask6);
            return r >= 0 ? r : -1;
    }
    SCLogDebug("invalid CIDR address format: %s", cidr_str);
    return -1;
}

/**
 * \brief Remove a CIDR string from a dataset
 * \param set The dataset
 * \param cidr_str CIDR string (e.g., "192.168.1.0/24" or "2001:db8::/32")
 * \retval 1 if removed, 0 if not present
 * \retval -1 on error
 */
int DatasetRemoveCIDRString(Dataset *set, const char *cidr_str)
{
    if (cidr_str == NULL)
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr v4;
    struct in6_addr v6;
    int mask4 = 0, mask6 = 0;
    switch (ParseCIDRAny(cidr_str, &v4, &mask4, &v6, &mask6)) {
        case 1:
            return CIDRRemoveIPv4Netblock(
                           &cidr->ipv4, (const uint8_t *)&v4.s_addr, (uint8_t)mask4)
                           ? 1
                           : 0;
        case 2:
            return CIDRRemoveIPv6Netblock(
                           &cidr->ipv6, (const uint8_t *)&v6.s6_addr, (uint8_t)mask6)
                           ? 1
                           : 0;
    }
    SCLogDebug("invalid CIDR address format: %s", cidr_str);
    return -1;
}

/**
 * \brief Look up an IP address in a CIDR dataset
 * \param set The dataset
 * \param ip_str IP string (e.g., "192.168.1.5" or "2001:db8::1")
 * \retval 1 if found
 * \retval 0 if not found
 * \retval -1 on error
 */
int DatasetLookupCIDRString(Dataset *set, const char *ip_str)
{
    if (ip_str == NULL || *ip_str == '\0')
        return -1;
    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;

    struct in_addr v4;
    if (inet_pton(AF_INET, ip_str, &v4) == 1)
        return CIDRLookupIPv4(&cidr->ipv4, (uint8_t *)&v4.s_addr) ? 1 : 0;

    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip_str, &v6) == 1)
        return CIDRLookupIPv6(&cidr->ipv6, (uint8_t *)&v6.s6_addr) ? 1 : 0;

    SCLogDebug("invalid IP address format: %s", ip_str);
    return -1;
}

/* Per-entry parsed buckets used only inside DatasetAddCIDRBatch. */
typedef struct {
    uint8_t addr[4];
    uint8_t prefix;
} CIDRBatchV4;

typedef struct {
    uint8_t addr[16];
    uint8_t prefix;
} CIDRBatchV6;

int DatasetAddCIDRBatch(
        Dataset *set, const char **cidr_strs, size_t n, CIDRBatchResult *out)
{
    if (out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));

    CIDRType *cidr = CIDRFromDataset(set);
    if (cidr == NULL)
        return -1;
    if (n == 0)
        return 0;

    /* Two-pass parse. Pass 1 classifies each input to size the per-family
     * buckets exactly; homogeneous v4-only or v6-only batches then use
     * O(n * sizeof one-struct) memory instead of O(n * sum-of-both).
     * Cost: each valid string is parsed twice. Bulk import isn't parse-
     * bound (the wrlock hold dominates), so trading CPU for peak memory
     * is the right call here. */
    size_t n4 = 0, n6 = 0;
    for (size_t i = 0; i < n; i++) {
        if (cidr_strs[i] == NULL)
            continue;
        struct in_addr in4;
        struct in6_addr in6;
        int mask;
        if (ParseCIDRString(cidr_strs[i], AF_INET, &in4, &mask, 32) == 0)
            n4++;
        else if (ParseCIDRString(cidr_strs[i], AF_INET6, &in6, &mask, 128) == 0)
            n6++;
    }

    CIDRBatchV4 *v4 = (n4 > 0) ? SCCalloc(n4, sizeof(*v4)) : NULL;
    CIDRBatchV6 *v6 = (n6 > 0) ? SCCalloc(n6, sizeof(*v6)) : NULL;
    if ((n4 > 0 && v4 == NULL) || (n6 > 0 && v6 == NULL)) {
        SCFree(v4);
        SCFree(v6);
        return -1;
    }

    /* Pass 2: re-parse and fill. Anything that failed pass 1 fails again
     * here and increments out->failed. */
    size_t j4 = 0, j6 = 0;
    for (size_t i = 0; i < n; i++) {
        if (cidr_strs[i] == NULL) {
            out->failed++;
            continue;
        }
        struct in_addr in4;
        struct in6_addr in6;
        int mask;
        if (ParseCIDRString(cidr_strs[i], AF_INET, &in4, &mask, 32) == 0) {
            memcpy(v4[j4].addr, &in4.s_addr, 4);
            v4[j4].prefix = (uint8_t)mask;
            if (v4[j4].prefix < 32)
                MaskIPNetblock(v4[j4].addr, v4[j4].prefix, 32);
            j4++;
        } else if (ParseCIDRString(cidr_strs[i], AF_INET6, &in6, &mask, 128) == 0) {
            memcpy(v6[j6].addr, &in6.s6_addr, 16);
            v6[j6].prefix = (uint8_t)mask;
            if (v6[j6].prefix < 128)
                MaskIPNetblock(v6[j6].addr, v6[j6].prefix, 128);
            j6++;
        } else {
            out->failed++;
        }
    }

    /* Phase 2: one wrlock per non-empty family for the whole batch. */
    if (n4 > 0) {
        SCRWLockWRLock(&cidr->ipv4.lock);
        for (size_t i = 0; i < n4; i++) {
            void *ud = NULL;
            if (SCRadix4TreeFindNetblock(
                        &cidr->ipv4.tree, v4[i].addr, v4[i].prefix, &ud) != NULL) {
                out->existed++;
                continue;
            }
            if (cidr_reserve_entry(&cidr->ipv4.bytes_sc_atomic__,
                        &cidr->ipv4.rejected_sc_atomic__, cidr->ipv4.memcap,
                        CIDR_IPV4_ENTRY_BYTES, set->name, "IPv4") != 0) {
                out->rejected_memcap++;
                continue;
            }
            if (SCRadix4AddKeyIPV4Netblock(&cidr->ipv4.tree, &radix4_cfg, v4[i].addr,
                        v4[i].prefix, NULL) == NULL) {
                cidr_release_entry(&cidr->ipv4.bytes_sc_atomic__, CIDR_IPV4_ENTRY_BYTES);
                out->failed++;
            } else {
                out->added++;
            }
        }
        SCRWLockUnlock(&cidr->ipv4.lock);
    }

    if (n6 > 0) {
        SCRWLockWRLock(&cidr->ipv6.lock);
        for (size_t i = 0; i < n6; i++) {
            void *ud = NULL;
            if (SCRadix6TreeFindNetblock(
                        &cidr->ipv6.tree, v6[i].addr, v6[i].prefix, &ud) != NULL) {
                out->existed++;
                continue;
            }
            if (cidr_reserve_entry(&cidr->ipv6.bytes_sc_atomic__,
                        &cidr->ipv6.rejected_sc_atomic__, cidr->ipv6.memcap,
                        CIDR_IPV6_ENTRY_BYTES, set->name, "IPv6") != 0) {
                out->rejected_memcap++;
                continue;
            }
            if (SCRadix6AddKeyIPV6Netblock(&cidr->ipv6.tree, &radix6_cfg, v6[i].addr,
                        v6[i].prefix, NULL) == NULL) {
                cidr_release_entry(&cidr->ipv6.bytes_sc_atomic__, CIDR_IPV6_ENTRY_BYTES);
                out->failed++;
            } else {
                out->added++;
            }
        }
        SCRWLockUnlock(&cidr->ipv6.lock);
    }

    SCFree(v4);
    SCFree(v6);
    return 0;
}
