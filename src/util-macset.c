/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 *
 * Set-like data store for MAC addresses. Implemented as array for memory
 * locality reasons as the expected number of items is typically low.
 *
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#endif
#include "flow-util.h"
#include "flow-private.h"
#include "flow-storage.h"
#include "util-macset.h"

typedef uint8_t MacAddr[6];
typedef enum {
    EMPTY_SET,  /* no address inserted yet */
    SINGLE_MAC, /* we have a single pair of addresses (likely) */
    MULTI_MAC   /* we have multiple addresses per flow */
} MacSetState;

struct MacSet_ {
    /* static store for a single MAC address per side */
    MacAddr singles[2];
    /* state determines how addresses are stored per side:
         - SINGLE_MAC uses static locations allocated with the MacSet
           itself to store a single address (most likely case)
         - MULTI_MAC is used when more than one distinct address
           is detected (causes another allocation and linear-time add) */
    MacSetState state[2];
    /* buffer for multiple MACs per flow and direction */
    MacAddr *buf[2];
    int size,
        last[2];
};

FlowStorageId g_macset_storage_id = { .id = -1 };

void MacSetRegisterFlowStorage(void)
{
    ConfNode *root = ConfGetNode("outputs");
    ConfNode *node = NULL;
    /* we only need to register if at least one enabled 'eve-log' output
       has the ethernet setting enabled */
    if (root != NULL) {
        TAILQ_FOREACH(node, &root->head, next) {
            if (node->val && strcmp(node->val, "eve-log") == 0) {
                const char *enabled = ConfNodeLookupChildValue(node->head.tqh_first, "enabled");
                if (enabled != NULL && ConfValIsTrue(enabled)) {
                    const char *ethernet = ConfNodeLookupChildValue(node->head.tqh_first, "ethernet");
                    if (ethernet != NULL && ConfValIsTrue(ethernet)) {
                        g_macset_storage_id = FlowStorageRegister("macset", sizeof(void *),
                                                                  NULL, (void(*)(void *)) MacSetFree);
                        return;
                    }
                }
            }
        }
    }
}

bool MacSetFlowStorageEnabled(void)
{
    return (g_macset_storage_id.id != -1);
}


MacSet *MacSetInit(int size)
{
    MacSet *ms = NULL;
    if (!FLOW_CHECK_MEMCAP(sizeof(*ms))) {
        return NULL;
    }
    ms = SCCalloc(1, sizeof(*ms));
    if (unlikely(ms == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate MacSet memory");
        return NULL;
    }
    (void) SC_ATOMIC_ADD(flow_memuse, (sizeof(*ms)));
    ms->state[MAC_SET_SRC] = ms->state[MAC_SET_DST] = EMPTY_SET;
    if (size < 3) {
        /* we want to make sure we have at space for at least 3 items to
           fit MACs during the initial extension to MULTI_MAC storage */
        size = 3;
    }
    ms->size = size;
    ms->last[MAC_SET_SRC] = ms->last[MAC_SET_DST] = 0;
    return ms;
}

FlowStorageId MacSetGetFlowStorageID(void)
{
    return g_macset_storage_id;
}

static inline void MacUpdateEntry(MacSet *ms, uint8_t *addr, int side, ThreadVars *tv, uint16_t ctr)
{
    switch (ms->state[side]) {
        case EMPTY_SET:
            memcpy(ms->singles[side], addr, sizeof(MacAddr));;
            ms->state[side] = SINGLE_MAC;
            if (tv != NULL)
                StatsSetUI64(tv, ctr, 1);
            break;
        case SINGLE_MAC:
            if (unlikely(memcmp(addr, ms->singles[side], sizeof(MacAddr)) != 0)) {
                if (ms->buf[side] == NULL) {
                    if (!FLOW_CHECK_MEMCAP(ms->size * sizeof(MacAddr))) {
                        /* in this case there is not much we can do */
                        return;
                    }
                    ms->buf[side] = SCCalloc(ms->size, sizeof(MacAddr));
                    if (unlikely(ms->buf[side] == NULL)) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate "
                                                     "MacSet memory");
                        return;
                    }
                    (void) SC_ATOMIC_ADD(flow_memuse, (ms->size * sizeof(MacAddr)));
                }
                memcpy(ms->buf[side], ms->singles[side], sizeof(MacAddr));
                memcpy(ms->buf[side] + 1, addr, sizeof(MacAddr));
                ms->last[side] = 2;
                if (tv != NULL)
                    StatsSetUI64(tv, ctr, 2);
                ms->state[side] = MULTI_MAC;
            }
            break;
        case MULTI_MAC:
            if (unlikely(ms->last[side] == ms->size)) {
                /* MacSet full, ignore item. We intentionally do not output
                   any warning in order not to stall packet processing */
                return;
            }
            /* If the set is non-empty... */
            if (ms->last[side] > 0) {
                /* ...we search for duplicates in the set to decide whether
                   we need to insert the current item. We do this backwards,
                   since we expect the latest item to match more likely than
                   the first */
                for (int i = ms->last[side] - 1; i >= 0; i--) {
                    uint8_t *addr2 = (uint8_t*) ((ms->buf[side]) + i);
                    /* If we find a match, we return early with no action */
                    if (likely(memcmp(addr2, addr, sizeof(MacAddr)) == 0)) {
                        return;
                    }
                }
            }
            /* Otherwise, we insert the new address at the end */
            memcpy(ms->buf[side] + ms->last[side], addr, sizeof(MacAddr));
            ms->last[side]++;
            if (tv != NULL)
                StatsSetUI64(tv, ctr, ms->last[side]);
            break;
    }
}

void MacSetAddWithCtr(MacSet *ms, uint8_t *src_addr, uint8_t *dst_addr, ThreadVars *tv,
                      uint16_t ctr_src, uint16_t ctr_dst)
{
    if (ms == NULL)
        return;
    MacUpdateEntry(ms, src_addr, MAC_SET_SRC, tv, ctr_src);
    MacUpdateEntry(ms, dst_addr, MAC_SET_DST, tv, ctr_dst);
}

void MacSetAdd(MacSet *ms, uint8_t *src_addr, uint8_t *dst_addr)
{
    MacSetAddWithCtr(ms, src_addr, dst_addr, NULL, 0, 0);
}

static inline int MacSetIterateSide(const MacSet *ms, MacSetIteratorFunc IterFunc,
                                    MacSetSide side, void *data)
{
    int ret = 0;
    switch (ms->state[side]) {
        case EMPTY_SET:
            return 0;
        case SINGLE_MAC:
            ret = IterFunc((uint8_t*) ms->singles[side], side, data);
            if (unlikely(ret != 0)) {
                return ret;
            }
            break;
        case MULTI_MAC:
            for (int i = 0; i < ms->last[side]; i++) {
                ret = IterFunc((uint8_t*) ms->buf[side][i], side, data);
                if (unlikely(ret != 0)) {
                    return ret;
                }
            }
            break;
    }
    return 0;
}

int MacSetForEach(const MacSet *ms, MacSetIteratorFunc IterFunc, void *data)
{
    int ret = 0;
    if (ms == NULL)
        return 0;

    ret = MacSetIterateSide(ms, IterFunc, MAC_SET_SRC, data);
    if (ret != 0) {
        return ret;
    }
    return MacSetIterateSide(ms, IterFunc, MAC_SET_DST, data);
}

int MacSetSize(const MacSet *ms)
{
    int size = 0;
    if (ms == NULL)
        return 0;

    switch(ms->state[MAC_SET_SRC]) {
        case EMPTY_SET:
            /* pass */
            break;
        case SINGLE_MAC:
            size += 1;
            break;
        case MULTI_MAC:
            size += ms->last[MAC_SET_SRC];
            break;
    }
    switch(ms->state[MAC_SET_DST]) {
        case EMPTY_SET:
            /* pass */
            break;
        case SINGLE_MAC:
            size += 1;
            break;
        case MULTI_MAC:
            size += ms->last[MAC_SET_DST];
            break;
    }
    return size;
}

void MacSetReset(MacSet *ms)
{
    if (ms == NULL)
        return;
    ms->state[MAC_SET_SRC] = ms->state[MAC_SET_DST] = EMPTY_SET;
    ms->last[MAC_SET_SRC] = ms->last[MAC_SET_DST] = 0;
}

void MacSetFree(MacSet *ms)
{
    size_t total_free = 0;
    if (ms == NULL)
        return;
    if (ms->buf[MAC_SET_SRC] != NULL) {
        SCFree(ms->buf[MAC_SET_SRC]);
        total_free += ms->size * sizeof(MacAddr);
    }
    if (ms->buf[MAC_SET_DST] != NULL) {
        SCFree(ms->buf[MAC_SET_DST]);
        total_free += ms->size * sizeof(MacAddr);
    }
    SCFree(ms);
    total_free += sizeof(*ms);
    (void) SC_ATOMIC_SUB(flow_memuse, total_free);
}

#ifdef UNITTESTS

static int CheckTest1Membership(uint8_t *addr, MacSetSide side, void *data)
{
    int *i = (int*) data;
    switch (*i) {
        case 0:
            if (addr[5] != 1) return 1;
            break;
        case 1:
            if (addr[5] != 2) return 1;
            break;
        case 2:
            if (addr[5] != 3) return 1;
            break;
    }
    (*i)++;
    return 0;
}

static int MacSetTest01(void)
{
    MacSet *ms = NULL;
    int ret = 0, i = 0;
    MacAddr addr1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
            addr2 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x2},
            addr3 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x3};
    SC_ATOMIC_SET(flow_config.memcap, 10000);

    ms = MacSetInit(10);
    FAIL_IF_NULL(ms);
    FAIL_IF_NOT(MacSetSize(ms) == 0);

    ret = MacSetForEach(ms, CheckTest1Membership, &i);
    FAIL_IF_NOT(ret == 0);

    MacSetAdd(ms, addr1, addr2);
    FAIL_IF_NOT(MacSetSize(ms) == 2);

    ret = MacSetForEach(ms, CheckTest1Membership, &i);
    FAIL_IF_NOT(ret == 0);

    MacSetAdd(ms, addr1, addr3);
    FAIL_IF_NOT(MacSetSize(ms) == 3);

    i = 0;
    ret = MacSetForEach(ms, CheckTest1Membership, &i);
    FAIL_IF_NOT(ret == 0);

    MacSetReset(ms);
    FAIL_IF_NOT(MacSetSize(ms) == 0);

    MacSetAdd(ms, addr2, addr3);
    FAIL_IF_NOT(MacSetSize(ms) == 2);

    i = 1;
    ret = MacSetForEach(ms, CheckTest1Membership, &i);
    FAIL_IF_NOT(ret == 0);

    MacSetFree(ms);
    PASS;
}

static int MacSetTest02(void)
{
    MacSet *ms = NULL;
    int ret = 0, i = 0;
    SC_ATOMIC_SET(flow_config.memcap, 10000);

    ms = MacSetInit(10);
    FAIL_IF_NULL(ms);
    FAIL_IF_NOT(MacSetSize(ms) == 0);

    for (i = 1; i < 100; i++) {
        MacAddr addr1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
                addr2 = {0x1, 0x0, 0x0, 0x0, 0x0, 0x2};
        MacSetAdd(ms, addr1, addr2);
    }
    FAIL_IF_NOT(MacSetSize(ms) == 2);

    ret = MacSetForEach(ms, CheckTest1Membership, &i);
    FAIL_IF_NOT(ret == 0);

    MacSetFree(ms);
    PASS;
}

static int MacSetTest03(void)
{
    MacSet *ms = NULL;
    SC_ATOMIC_SET(flow_config.memcap, 10000);

    ms = MacSetInit(10);
    FAIL_IF_NULL(ms);
    FAIL_IF_NOT(MacSetSize(ms) == 0);

    for (uint8_t i = 1; i < 100; i++) {
        MacAddr addr1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
                addr2 = {0x1, 0x0, 0x0, 0x0, 0x0, 0x1};
        addr1[5] = i;
        addr2[5] = i;
        MacSetAdd(ms, addr1, addr2);
    }
    FAIL_IF_NOT(MacSetSize(ms) == 20);

    MacSetFree(ms);
    PASS;
}

static int MacSetTest04(void)
{
    MacSet *ms = NULL;
    SC_ATOMIC_SET(flow_config.memcap, 2);

    ms = MacSetInit(10);
    FAIL_IF_NOT_NULL(ms);

    PASS;
}

static int MacSetTest05(void)
{
    MacSet *ms = NULL;
    int ret = 0;
    SC_ATOMIC_SET(flow_config.memcap, 64);

    ms = MacSetInit(10);
    FAIL_IF_NULL(ms);
    FAIL_IF_NOT(MacSetSize(ms) == 0);

    for (uint8_t i = 1; i < 100; i++) {
        MacAddr addr1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
                addr2 = {0x1, 0x0, 0x0, 0x0, 0x0, 0x1};
        addr1[5] = i;
        addr2[5] = i;
        MacSetAdd(ms, addr1, addr2);
    }
    FAIL_IF_NOT(MacSetSize(ms) == 2);

    int i2 = 100;
    ret = MacSetForEach(ms, CheckTest1Membership, &i2);
    FAIL_IF_NOT(ret == 0);

    MacSetFree(ms);
    PASS;
}

#endif /* UNITTESTS */

void MacSetRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("MacSetTest01", MacSetTest01);
    UtRegisterTest("MacSetTest02", MacSetTest02);
    UtRegisterTest("MacSetTest03", MacSetTest03);
    UtRegisterTest("MacSetTest04", MacSetTest04);
    UtRegisterTest("MacSetTest05", MacSetTest05);
#endif

    return;
}
