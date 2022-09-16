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
 * Implements per host bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#include "util-debug.h"
#include "util-var.h"
#include "detect.h"
#include "host.h"
#include "threads.h"
#endif
#include "host-bit.h"
#include "host-storage.h"

static HostStorageId host_bit_id = { .id = -1 }; /**< Host storage id for bits */

static void HostBitFreeAll(void *store)
{
    GenericVar *gv = store;
    GenericVarFree(gv);
}

void HostBitInitCtx(void)
{
    host_bit_id = HostStorageRegister("bit", sizeof(void *), NULL, HostBitFreeAll);
    if (host_bit_id.id == -1) {
        FatalError(SC_ERR_FATAL, "Can't initiate host storage for bits");
    }
}

/* lock before using this */
int HostHasHostBits(Host *host)
{
    if (host == NULL)
        return 0;
    return HostGetStorageById(host, host_bit_id) ? 1 : 0;
}

/** \retval 1 host timed out wrt xbits
  * \retval 0 host still has active (non-expired) xbits */
int HostBitsTimedoutCheck(Host *h, struct timeval *ts)
{
    GenericVar *gv = HostGetStorageById(h, host_bit_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS) {
            XBit *xb = (XBit *)gv;
            if (xb->expire > (uint32_t)ts->tv_sec)
                return 0;
        }
    }
    return 1;
}

/* get the bit with idx from the host */
static XBit *HostBitGet(Host *h, uint32_t idx)
{
    GenericVar *gv = HostGetStorageById(h, host_bit_id);
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
            return (XBit *)gv;
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void HostBitAdd(Host *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(XBit));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_XBITS;
        fb->idx = idx;
        fb->next = NULL;
        fb->expire = expire;

        GenericVar *gv = HostGetStorageById(h, host_bit_id);
        GenericVarAppend(&gv, (GenericVar *)fb);
        HostSetStorageById(h, host_bit_id, gv);

    // bit already set, lets update it's time
    } else {
        fb->expire = expire;
    }
}

static void HostBitRemove(Host *h, uint32_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL)
        return;

    GenericVar *gv = HostGetStorageById(h, host_bit_id);
    if (gv) {
        GenericVarRemove(&gv, (GenericVar *)fb);
        XBitFree(fb);
        HostSetStorageById(h, host_bit_id, gv);
    }
}

void HostBitSet(Host *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        HostBitAdd(h, idx, expire);
    }
}

void HostBitUnset(Host *h, uint32_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        HostBitRemove(h, idx);
    }
}

void HostBitToggle(Host *h, uint32_t idx, uint32_t expire)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        HostBitRemove(h, idx);
    } else {
        HostBitAdd(h, idx, expire);
    }
}

int HostBitIsset(Host *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        if (fb->expire < ts) {
            HostBitRemove(h,idx);
            return 0;
        }
        return 1;
    }
    return 0;
}

int HostBitIsnotset(Host *h, uint32_t idx, uint32_t ts)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        return 1;
    }

    if (fb->expire < ts) {
        HostBitRemove(h,idx);
        return 1;
    }
    return 0;
}

int HostBitList(Host *h, XBit **iter)
{
    GenericVar *gv = (GenericVar *)*iter;
    if (gv == NULL) {
        gv = HostGetStorageById(h, host_bit_id);
    } else {
        gv = gv->next;
    }

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS) {
            *iter = (XBit *)gv;
            return 1;
        }
    }
    *iter = NULL;
    return 0;
}

/* TESTS */
#ifdef UNITTESTS
static int HostBitTest01 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 0);

    XBit *fb = HostBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest02 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    XBit *fb = HostBitGet(h,0);
    if (fb == NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest03 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 30);

    XBit *fb = HostBitGet(h,0);
    if (fb == NULL) {
        printf("fb == NULL although it was just added: ");
        goto end;
    }

    HostBitRemove(h, 0);

    fb = HostBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL although it was just removed: ");
        goto end;
    } else {
        ret = 1;
    }

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest04 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 30);
    HostBitAdd(h, 1, 30);
    HostBitAdd(h, 2, 30);
    HostBitAdd(h, 3, 30);

    XBit *fb = HostBitGet(h,0);
    if (fb != NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest05 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 30);
    HostBitAdd(h, 1, 30);
    HostBitAdd(h, 2, 30);
    HostBitAdd(h, 3, 30);

    XBit *fb = HostBitGet(h,1);
    if (fb != NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest06 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,2);
    if (fb != NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest07 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,3);
    if (fb != NULL)
        ret = 1;

    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest08 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,0);
    if (fb == NULL)
        goto end;

    HostBitRemove(h,0);

    fb = HostBitGet(h,0);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest09 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,1);
    if (fb == NULL)
        goto end;

    HostBitRemove(h,1);

    fb = HostBitGet(h,1);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest10 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,2);
    if (fb == NULL)
        goto end;

    HostBitRemove(h,2);

    fb = HostBitGet(h,2);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    HostFree(h);
end:
    HostCleanup();
    return ret;
}

static int HostBitTest11 (void)
{
    int ret = 0;

    HostInitConfig(true);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0, 90);
    HostBitAdd(h, 1, 90);
    HostBitAdd(h, 2, 90);
    HostBitAdd(h, 3, 90);

    XBit *fb = HostBitGet(h,3);
    if (fb == NULL)
        goto end;

    HostBitRemove(h,3);

    fb = HostBitGet(h,3);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
    HostFree(h);
end:
    HostCleanup();
    return ret;
}

#endif /* UNITTESTS */

void HostBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HostBitTest01", HostBitTest01);
    UtRegisterTest("HostBitTest02", HostBitTest02);
    UtRegisterTest("HostBitTest03", HostBitTest03);
    UtRegisterTest("HostBitTest04", HostBitTest04);
    UtRegisterTest("HostBitTest05", HostBitTest05);
    UtRegisterTest("HostBitTest06", HostBitTest06);
    UtRegisterTest("HostBitTest07", HostBitTest07);
    UtRegisterTest("HostBitTest08", HostBitTest08);
    UtRegisterTest("HostBitTest09", HostBitTest09);
    UtRegisterTest("HostBitTest10", HostBitTest10);
    UtRegisterTest("HostBitTest11", HostBitTest11);
#endif /* UNITTESTS */
}
