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
 * Implements per host bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 */

#include "suricata-common.h"
#include "threads.h"
#include "host-bit.h"
#include "host.h"
#include "detect.h"
#include "util-var.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "host-storage.h"

static int host_bit_id = -1;                /**< Host storage id for bits */

void HostBitFreeAll(void *store) {
    GenericVar *gv = store;
    GenericVarFree(gv);
}

void HostBitInitCtx(void)
{
    host_bit_id = HostStorageRegister("bit", sizeof(void *), NULL, HostBitFreeAll);
    if (host_bit_id == -1) {
        SCLogError(SC_ERR_HOST_INIT, "Can't initiate host storage for bits");
        exit(EXIT_FAILURE);
    }
}

/* lock before using this */
int HostHasHostBits(Host *host)
{
    if (host == NULL)
        return 0;
    return HostGetStorageById(host, host_bit_id) ? 1 : 0;
}

/* get the bit with idx from the host */
static XBit *HostBitGet(Host *h, uint16_t idx)
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
static void HostBitAdd(Host *h, uint16_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(XBit));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_XBITS;
        fb->idx = idx;
        fb->next = NULL;

        GenericVar *gv = HostGetStorageById(h, host_bit_id);
        GenericVarAppend(&gv, (GenericVar *)fb);
        HostSetStorageById(h, host_bit_id, gv);
    }
}

static void HostBitRemove(Host *h, uint16_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL)
        return;

    GenericVar *gv = HostGetStorageById(h, host_bit_id);
    if (gv) {
        GenericVarRemove(&gv, (GenericVar *)fb);
        HostSetStorageById(h, host_bit_id, gv);
    }
}

void HostBitSet(Host *h, uint16_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        HostBitAdd(h, idx);
    }
}

void HostBitUnset(Host *h, uint16_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        HostBitRemove(h, idx);
    }
}

void HostBitToggle(Host *h, uint16_t idx)
{
    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        HostBitRemove(h, idx);
    } else {
        HostBitAdd(h, idx);
    }
}

int HostBitIsset(Host *h, uint16_t idx)
{
    int r = 0;

    XBit *fb = HostBitGet(h, idx);
    if (fb != NULL) {
        r = 1;
    }
    return r;
}

int HostBitIsnotset(Host *h, uint16_t idx)
{
    int r = 0;

    XBit *fb = HostBitGet(h, idx);
    if (fb == NULL) {
        r = 1;
    }

    return r;
}

/* TESTS */
#ifdef UNITTESTS
static int HostBitTest01 (void)
{
    int ret = 0;

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);

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

    HostInitConfig(TRUE);
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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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

    HostInitConfig(TRUE);
    Host *h = HostAlloc();
    if (h == NULL)
        goto end;

    HostBitAdd(h, 0);
    HostBitAdd(h, 1);
    HostBitAdd(h, 2);
    HostBitAdd(h, 3);

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
    ret = 1;
    return ret;
}

#endif /* UNITTESTS */

void HostBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HostBitTest01", HostBitTest01, 1);
    UtRegisterTest("HostBitTest02", HostBitTest02, 1);
    UtRegisterTest("HostBitTest03", HostBitTest03, 1);
    UtRegisterTest("HostBitTest04", HostBitTest04, 1);
    UtRegisterTest("HostBitTest05", HostBitTest05, 1);
    UtRegisterTest("HostBitTest06", HostBitTest06, 1);
    UtRegisterTest("HostBitTest07", HostBitTest07, 1);
    UtRegisterTest("HostBitTest08", HostBitTest08, 1);
    UtRegisterTest("HostBitTest09", HostBitTest09, 1);
    UtRegisterTest("HostBitTest10", HostBitTest10, 1);
    UtRegisterTest("HostBitTest11", HostBitTest11, 1);
#endif /* UNITTESTS */
}
