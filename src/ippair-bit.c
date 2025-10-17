/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 *
 * Implements per ippair bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 */

#include "suricata-common.h"
#include "threads.h"
#include "ippair-bit.h"
#include "ippair.h"
#include "detect.h"
#include "util-var.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "ippair-storage.h"

static IPPairStorageId g_ippair_bit_storage_id = { .id = -1 }; /**< IPPair storage id for bits */

static void XBitFreeAll(void *store)
{
    GenericVar *gv = store;
    SCGenericVarFree(gv);
}

void IPPairBitInitCtx(void)
{
    g_ippair_bit_storage_id = IPPairStorageRegister("bit", sizeof(void *), NULL, XBitFreeAll);
    if (g_ippair_bit_storage_id.id == -1) {
        FatalError("Can't initiate ippair storage for bits");
    }
}

/* lock before using this */
int IPPairHasBits(IPPair *ippair)
{
    if (ippair == NULL)
        return 0;
    return IPPairGetStorageById(ippair, g_ippair_bit_storage_id) ? 1 : 0;
}

/** \retval 1 ippair timed out wrt xbits
  * \retval 0 ippair still has active (non-expired) xbits */
int IPPairBitsTimedoutCheck(IPPair *h, SCTime_t ts)
{
    GenericVar *gv = IPPairGetStorageById(h, g_ippair_bit_storage_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS) {
            XBit *xb = (XBit *)gv;
            if (SCTIME_CMP_GT(xb->expire, ts))
                return 0;
        }
    }
    return 1;
}

/* get the bit with idx from the ippair */
static XBit *IPPairBitGet(IPPair *h, uint32_t idx)
{
    GenericVar *gv = IPPairGetStorageById(h, g_ippair_bit_storage_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
            return (XBit *)gv;
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void IPPairBitAdd(IPPair *h, uint32_t idx, SCTime_t expire)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(XBit));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_XBITS;
        fb->idx = idx;
        fb->next = NULL;
        fb->expire = expire;

        GenericVar *gv = IPPairGetStorageById(h, g_ippair_bit_storage_id);
        GenericVarAppend(&gv, (GenericVar *)fb);
        IPPairSetStorageById(h, g_ippair_bit_storage_id, gv);

        // bit already set, lets update it's timer
    } else {
        fb->expire = expire;
    }
}

static void IPPairBitRemove(IPPair *h, uint32_t idx)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb == NULL)
        return;

    GenericVar *gv = IPPairGetStorageById(h, g_ippair_bit_storage_id);
    if (gv) {
        GenericVarRemove(&gv, (GenericVar *)fb);
        XBitFree(fb);
        IPPairSetStorageById(h, g_ippair_bit_storage_id, gv);
    }
}

void IPPairBitSet(IPPair *h, uint32_t idx, SCTime_t expire)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb == NULL) {
        IPPairBitAdd(h, idx, expire);
    }
}

void IPPairBitUnset(IPPair *h, uint32_t idx)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb != NULL) {
        IPPairBitRemove(h, idx);
    }
}

void IPPairBitToggle(IPPair *h, uint32_t idx, SCTime_t expire)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb != NULL) {
        IPPairBitRemove(h, idx);
    } else {
        IPPairBitAdd(h, idx, expire);
    }
}

int IPPairBitIsset(IPPair *h, uint32_t idx, SCTime_t ts)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb != NULL) {
        if (SCTIME_CMP_LT(fb->expire, ts)) {
            IPPairBitRemove(h, idx);
            return 0;
        }

        return 1;
    }
    return 0;
}

int IPPairBitIsnotset(IPPair *h, uint32_t idx, SCTime_t ts)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb == NULL) {
        return 1;
    }

    if (SCTIME_CMP_LT(fb->expire, ts)) {
        IPPairBitRemove(h, idx);
        return 1;
    }

    return 0;
}


/* TESTS */
#ifdef UNITTESTS
static int IPPairBitTest01 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(0));

    XBit *fb = IPPairBitGet(h,0);
    FAIL_IF_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest02 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    XBit *fb = IPPairBitGet(h,0);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest03 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(30));

    XBit *fb = IPPairBitGet(h,0);
    FAIL_IF_NULL(fb);

    IPPairBitRemove(h, 0);

    fb = IPPairBitGet(h,0);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest04 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(30));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(30));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(30));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(30));

    XBit *fb = IPPairBitGet(h,0);
    FAIL_IF_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest05 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,1);
    FAIL_IF_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest06 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,2);
    FAIL_IF_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest07 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,3);
    FAIL_IF_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest08 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,0);
    FAIL_IF_NULL(fb);

    IPPairBitRemove(h,0);

    fb = IPPairBitGet(h,0);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest09 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,1);
    FAIL_IF_NULL(fb);

    IPPairBitRemove(h,1);

    fb = IPPairBitGet(h,1);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest10 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,2);
    FAIL_IF_NULL(fb);

    IPPairBitRemove(h,2);

    fb = IPPairBitGet(h,2);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

static int IPPairBitTest11 (void)
{
    StorageCleanup();
    StorageInit();
    IPPairBitInitCtx();
    StorageFinalize();
    IPPairInitConfig(true);
    IPPair *h = IPPairAlloc();
    FAIL_IF_NULL(h);

    IPPairBitAdd(h, 0, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 1, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 2, SCTIME_FROM_SECS(90));
    IPPairBitAdd(h, 3, SCTIME_FROM_SECS(90));

    XBit *fb = IPPairBitGet(h,3);
    FAIL_IF_NULL(fb);

    IPPairBitRemove(h,3);

    fb = IPPairBitGet(h,3);
    FAIL_IF_NOT_NULL(fb);

    IPPairFree(h);
    IPPairShutdown();
    StorageCleanup();
    PASS;
}

#endif /* UNITTESTS */

void IPPairBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IPPairBitTest01", IPPairBitTest01);
    UtRegisterTest("IPPairBitTest02", IPPairBitTest02);
    UtRegisterTest("IPPairBitTest03", IPPairBitTest03);
    UtRegisterTest("IPPairBitTest04", IPPairBitTest04);
    UtRegisterTest("IPPairBitTest05", IPPairBitTest05);
    UtRegisterTest("IPPairBitTest06", IPPairBitTest06);
    UtRegisterTest("IPPairBitTest07", IPPairBitTest07);
    UtRegisterTest("IPPairBitTest08", IPPairBitTest08);
    UtRegisterTest("IPPairBitTest09", IPPairBitTest09);
    UtRegisterTest("IPPairBitTest10", IPPairBitTest10);
    UtRegisterTest("IPPairBitTest11", IPPairBitTest11);
#endif /* UNITTESTS */
}
