/* Copyright (C) 2014 Open Information Security Foundation
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

static int ippair_bit_id = -1;                /**< IPPair storage id for bits */

static void XBitFreeAll(void *store)
{
    GenericVar *gv = store;
    GenericVarFree(gv);
}

void IPPairBitInitCtx(void)
{
    ippair_bit_id = IPPairStorageRegister("bit", sizeof(void *), NULL, XBitFreeAll);
    if (ippair_bit_id == -1) {
        SCLogError(SC_ERR_IPPAIR_INIT, "Can't initiate ippair storage for bits");
        exit(EXIT_FAILURE);
    }
}

/* lock before using this */
int IPPairHasBits(IPPair *ippair)
{
    if (ippair == NULL)
        return 0;
    return IPPairGetStorageById(ippair, ippair_bit_id) ? 1 : 0;
}

/** \retval 1 ippair timed out wrt xbits
  * \retval 0 ippair still has active (non-expired) xbits */
int IPPairBitsTimedoutCheck(IPPair *h, struct timeval *ts)
{
    GenericVar *gv = IPPairGetStorageById(h, ippair_bit_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS) {
            XBit *xb = (XBit *)gv;
            if (xb->expire > (uint32_t)ts->tv_sec)
                return 0;
        }
    }
    return 1;
}

/* get the bit with idx from the ippair */
static XBit *IPPairBitGet(IPPair *h, uint32_t idx)
{
    GenericVar *gv = IPPairGetStorageById(h, ippair_bit_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
            return (XBit *)gv;
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void IPPairBitAdd(IPPair *h, uint32_t idx, uint32_t expire)
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

        GenericVar *gv = IPPairGetStorageById(h, ippair_bit_id);
        GenericVarAppend(&gv, (GenericVar *)fb);
        IPPairSetStorageById(h, ippair_bit_id, gv);

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

    GenericVar *gv = IPPairGetStorageById(h, ippair_bit_id);
    if (gv) {
        GenericVarRemove(&gv, (GenericVar *)fb);
        XBitFree(fb);
        IPPairSetStorageById(h, ippair_bit_id, gv);
    }
}

void IPPairBitSet(IPPair *h, uint32_t idx, uint32_t expire)
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

void IPPairBitToggle(IPPair *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb != NULL) {
        IPPairBitRemove(h, idx);
    } else {
        IPPairBitAdd(h, idx, expire);
    }
}

int IPPairBitIsset(IPPair *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb != NULL) {
        if (fb->expire < ts) {
            IPPairBitRemove(h, idx);
            return 0;
        }

        return 1;
    }
    return 0;
}

int IPPairBitIsnotset(IPPair *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = IPPairBitGet(h, idx);
    if (fb == NULL) {
        return 1;
    }

    if (fb->expire < ts) {
        IPPairBitRemove(h, idx);
        return 1;
    }

    return 0;
}


/* TESTS */
#ifdef UNITTESTS
static int IPPairBitTest01 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0, 0);

    XBit *fb = IPPairBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest02 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    XBit *fb = IPPairBitGet(h,0);
    if (fb == NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest03 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0, 30);

    XBit *fb = IPPairBitGet(h,0);
    if (fb == NULL) {
        printf("fb == NULL although it was just added: ");
        goto end;
    }

    IPPairBitRemove(h, 0);

    fb = IPPairBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL although it was just removed: ");
        goto end;
    } else {
        ret = 1;
    }

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest04 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,30);
    IPPairBitAdd(h, 1,30);
    IPPairBitAdd(h, 2,30);
    IPPairBitAdd(h, 3,30);

    XBit *fb = IPPairBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest05 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,1);
    if (fb != NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest06 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,2);
    if (fb != NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest07 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,3);
    if (fb != NULL)
        ret = 1;

    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest08 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,0);
    if (fb == NULL)
        goto end;

    IPPairBitRemove(h,0);

    fb = IPPairBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest09 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,1);
    if (fb == NULL)
        goto end;

    IPPairBitRemove(h,1);

    fb = IPPairBitGet(h,1);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest10 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,2);
    if (fb == NULL)
        goto end;

    IPPairBitRemove(h,2);

    fb = IPPairBitGet(h,2);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
}

static int IPPairBitTest11 (void)
{
    int ret = 0;

    IPPairInitConfig(TRUE);
    IPPair *h = IPPairAlloc();
    if (h == NULL)
        goto end;

    IPPairBitAdd(h, 0,90);
    IPPairBitAdd(h, 1,90);
    IPPairBitAdd(h, 2,90);
    IPPairBitAdd(h, 3,90);

    XBit *fb = IPPairBitGet(h,3);
    if (fb == NULL)
        goto end;

    IPPairBitRemove(h,3);

    fb = IPPairBitGet(h,3);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    IPPairFree(h);
end:
    IPPairCleanup();
    return ret;
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
