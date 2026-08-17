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

#include "../suricata-common.h"
#include "../util-unittest.h"

/* Build a fake rx ring in one block of memory. The ring header and its slots
 * come first and the packet buffers follow, so NETMAP_BUF(ring, k) lands on
 * buffer number k. num_slots and nr_buf_size are const in the real struct, so
 * we write them through a plain pointer as the memory itself is not const. */
static struct netmap_ring *NetmapTestRingNew(uint32_t num_slots, uint32_t buf_size)
{
    size_t slots_end =
            offsetof(struct netmap_ring, slot) + (size_t)num_slots * sizeof(struct netmap_slot);
    size_t total = slots_end + (size_t)num_slots * buf_size;

    struct netmap_ring *ring = SCCalloc(1, total);
    if (ring == NULL)
        return NULL;

    *(int64_t *)(uintptr_t)&ring->buf_ofs = (int64_t)slots_end;
    *(uint32_t *)(uintptr_t)&ring->num_slots = num_slots;
    *(uint32_t *)(uintptr_t)&ring->nr_buf_size = buf_size;
    ring->head = ring->cur = 0;
    /* mark all but one slot as owned by us so nm_ring_space is not zero */
    ring->tail = num_slots ? num_slots - 1 : 0;
    return ring;
}

/* Point a slot at buffer buf_idx, give it a length and flags, and fill that
 * buffer with a byte so we can check the order things get copied in. */
static void NetmapTestSetSlot(struct netmap_ring *ring, uint32_t slot_idx, uint32_t buf_idx,
        uint16_t len, uint16_t flags, uint8_t fill)
{
    ring->slot[slot_idx].buf_idx = buf_idx;
    ring->slot[slot_idx].len = len;
    ring->slot[slot_idx].flags = flags;
    memset(NETMAP_BUF(ring, buf_idx), fill, len);
}

static void NetmapTestNtvInit(NetmapThreadVars *ntv, uint32_t coalesce_size)
{
    memset(ntv, 0, sizeof(*ntv));
    ntv->coalesce_size = coalesce_size;
    ntv->coalesce_buf = SCCalloc(1, coalesce_size);
    if (ntv->coalesce_buf == NULL)
        return;
}

/* One slot, no fragments. It should stay as is and keep pointing into the ring
 * so zero-copy is still possible. */
static int NetmapReadSingleSlotTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 0, 100, 0, 0xAA);

    struct nm_pkthdr hdr;
    bool force_copy = true;
    FAIL_IF_NOT(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF(force_copy);
    FAIL_IF_NOT(hdr.len == 100);
    FAIL_IF_NOT(hdr.buf == (u_char *)NETMAP_BUF(ring, 0));
    FAIL_IF_NOT(ring->cur == 1);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* Two fragments whose buffers happen to sit next to each other. The whole frame
 * must be rebuilt in the coalesce buffer. */
static int NetmapReadTwoSlotAdjacentTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 0, 60, NS_MOREFRAG, 0x11);
    NetmapTestSetSlot(ring, 1, 1, 40, 0, 0x22);

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF_NOT(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(force_copy);
    FAIL_IF_NOT(hdr.len == 100);
    FAIL_IF_NOT(hdr.buf == ntv.coalesce_buf);
    for (uint32_t i = 0; i < 60; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x11);
    for (uint32_t i = 60; i < 100; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x22);
    FAIL_IF_NOT(ring->cur == 2);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* Two fragments whose buffers are far apart. This is the case the old code got
 * wrong. We must still copy the real bytes of both slots in order. */
static int NetmapReadTwoSlotNonAdjacentTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 5, 60, NS_MOREFRAG, 0x33);
    NetmapTestSetSlot(ring, 1, 2, 40, 0, 0x44);

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF_NOT(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(force_copy);
    FAIL_IF_NOT(hdr.len == 100);
    FAIL_IF_NOT(hdr.buf == ntv.coalesce_buf);
    for (uint32_t i = 0; i < 60; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x33);
    for (uint32_t i = 60; i < 100; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x44);
    FAIL_IF_NOT(ring->cur == 2);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* A two slot packet that wraps around the end of the ring (slot 3 then slot 0).
 * The walk has to follow the wrap and rebuild the frame. */
static int NetmapReadRingWrapTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(4, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 3, 3, 60, NS_MOREFRAG, 0x55);
    NetmapTestSetSlot(ring, 0, 0, 40, 0, 0x66);
    ring->head = ring->cur = 3;
    /* two slots owned, 3 then 0 */
    ring->tail = 1;

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF_NOT(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(force_copy);
    FAIL_IF_NOT(hdr.len == 100);
    FAIL_IF_NOT(hdr.buf == ntv.coalesce_buf);
    for (uint32_t i = 0; i < 60; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x55);
    for (uint32_t i = 60; i < 100; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x66);
    FAIL_IF_NOT(ring->cur == 1);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* An empty leading fragment must not break the copy of the following one. */
static int NetmapReadZeroLenFragTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 0, 0, NS_MOREFRAG, 0x00);
    NetmapTestSetSlot(ring, 1, 1, 50, 0, 0x77);

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF_NOT(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(force_copy);
    FAIL_IF_NOT(hdr.len == 50);
    for (uint32_t i = 0; i < 50; i++)
        FAIL_IF_NOT(ntv.coalesce_buf[i] == 0x77);
    FAIL_IF_NOT(ring->cur == 2);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* A frame bigger than the coalesce buffer must be dropped, not copied. */
static int NetmapReadOverSizeTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, 100);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 0, 60, NS_MOREFRAG, 0x11);
    NetmapTestSetSlot(ring, 1, 1, 60, 0, 0x22);

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(ntv.drops == 1);
    FAIL_IF_NOT(ring->cur == 2);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* An oversize frame with fragments after the point where it overflows must be
 * dropped whole, so the trailing slots are not read back as a bogus packet. */
static int NetmapReadOverSizeTrailingFragTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 2048);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, 100);
    FAIL_IF_NULL(ntv.coalesce_buf);

    NetmapTestSetSlot(ring, 0, 0, 60, NS_MOREFRAG, 0x11);
    NetmapTestSetSlot(ring, 1, 1, 60, NS_MOREFRAG, 0x22);
    NetmapTestSetSlot(ring, 2, 2, 20, 0, 0x33);

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(ntv.drops == 1);
    FAIL_IF_NOT(ring->cur == 3);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

/* A fragment chain that never ends must be dropped once we have looked at every
 * slot we own, and the ring must still move forward so the reader cannot spin. */
static int NetmapReadTooManyFragsTest(void)
{
    struct netmap_ring *ring = NetmapTestRingNew(8, 64);
    FAIL_IF_NULL(ring);
    NetmapThreadVars ntv;
    NetmapTestNtvInit(&ntv, MAX_PAYLOAD_SIZE);
    FAIL_IF_NULL(ntv.coalesce_buf);

    for (uint32_t k = 0; k < 5; k++)
        NetmapTestSetSlot(ring, k, k, 10, NS_MOREFRAG, (uint8_t)(0x10 + k));
    ring->head = ring->cur = 0;
    ring->tail = 5;

    struct nm_pkthdr hdr;
    bool force_copy = false;
    FAIL_IF(NetmapReadOnePacket(ring, &ntv, &hdr, &force_copy));
    FAIL_IF_NOT(ntv.drops == 1);
    FAIL_IF_NOT(ring->cur == 5);

    SCFree(ntv.coalesce_buf);
    SCFree(ring);
    PASS;
}

static void NetmapRegisterTests(void)
{
    UtRegisterTest("NetmapReadSingleSlotTest", NetmapReadSingleSlotTest);
    UtRegisterTest("NetmapReadTwoSlotAdjacentTest", NetmapReadTwoSlotAdjacentTest);
    UtRegisterTest("NetmapReadTwoSlotNonAdjacentTest", NetmapReadTwoSlotNonAdjacentTest);
    UtRegisterTest("NetmapReadRingWrapTest", NetmapReadRingWrapTest);
    UtRegisterTest("NetmapReadZeroLenFragTest", NetmapReadZeroLenFragTest);
    UtRegisterTest("NetmapReadOverSizeTest", NetmapReadOverSizeTest);
    UtRegisterTest("NetmapReadOverSizeTrailingFragTest", NetmapReadOverSizeTrailingFragTest);
    UtRegisterTest("NetmapReadTooManyFragsTest", NetmapReadTooManyFragsTest);
}
