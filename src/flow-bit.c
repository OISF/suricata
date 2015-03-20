/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Implements per flow bits. Actually, not a bit,
 * but called that way because of Snort's flowbits.
 * It's a binary storage.
 *
 * \todo move away from a linked list implementation
 * \todo use different datatypes, such as string, int, etc.
 * \todo have more than one instance of the same var, and be able to match on a
 *       specific one, or one all at a time. So if a certain capture matches
 *       multiple times, we can operate on all of them.
 */

#include "suricata-common.h"
#include "threads.h"
#include "flow-bit.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-private.h"
#include "detect.h"
#include "util-var.h"
#include "util-debug.h"
#include "util-unittest.h"

/* get the flowbit with idx from the flow */
static FlowBit *FlowBitGet(Flow *f, uint16_t idx)
{
    GenericVar *gv = f->flowvar;
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
            return (FlowBit *)gv;
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void FlowBitAdd(Flow *f, uint16_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(FlowBit));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_FLOWBITS;
        fb->idx = idx;
        fb->next = NULL;
        GenericVarAppend(&f->flowvar, (GenericVar *)fb);

        //printf("FlowBitAdd: adding flowbit with idx %" PRIu32 "\n", idx);
#ifdef FLOWBITS_STATS
        SCMutexLock(&flowbits_mutex);
        flowbits_added++;
        flowbits_memuse += sizeof(FlowBit);
        if (flowbits_memuse > flowbits_memuse_max)
            flowbits_memuse_max = flowbits_memuse;
        SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWBITS_STATS */
    }
}

static void FlowBitRemove(Flow *f, uint16_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL)
        return;

    GenericVarRemove(&f->flowvar, (GenericVar *)fb);

    //printf("FlowBitRemove: remove flowbit with idx %" PRIu32 "\n", idx);
#ifdef FLOWBITS_STATS
    SCMutexLock(&flowbits_mutex);
    flowbits_removed++;
    if (flowbits_memuse >= sizeof(FlowBit))
        flowbits_memuse -= sizeof(FlowBit);
    else {
        printf("ERROR: flowbits memory usage going below 0!\n");
        flowbits_memuse = 0;
    }
    SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWBITS_STATS */
}

void FlowBitSetNoLock(Flow *f, uint16_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL) {
        FlowBitAdd(f, idx);
    }
}

void FlowBitSet(Flow *f, uint16_t idx)
{
    FLOWLOCK_WRLOCK(f);
    FlowBitSetNoLock(f, idx);
    FLOWLOCK_UNLOCK(f);
}

void FlowBitUnsetNoLock(Flow *f, uint16_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb != NULL) {
        FlowBitRemove(f, idx);
    }
}

void FlowBitUnset(Flow *f, uint16_t idx)
{
    FLOWLOCK_WRLOCK(f);
    FlowBitUnsetNoLock(f, idx);
    FLOWLOCK_UNLOCK(f);
}

void FlowBitToggleNoLock(Flow *f, uint16_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb != NULL) {
        FlowBitRemove(f, idx);
    } else {
        FlowBitAdd(f, idx);
    }
}

void FlowBitToggle(Flow *f, uint16_t idx)
{
    FLOWLOCK_WRLOCK(f);
    FlowBitToggleNoLock(f, idx);
    FLOWLOCK_UNLOCK(f);
}

int FlowBitIsset(Flow *f, uint16_t idx)
{
    int r = 0;
    FLOWLOCK_RDLOCK(f);

    FlowBit *fb = FlowBitGet(f, idx);
    if (fb != NULL) {
        r = 1;
    }

    FLOWLOCK_UNLOCK(f);
    return r;
}

int FlowBitIsnotset(Flow *f, uint16_t idx)
{
    int r = 0;
    FLOWLOCK_RDLOCK(f);

    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL) {
        r = 1;
    }

    FLOWLOCK_UNLOCK(f);
    return r;
}

void FlowBitFree(FlowBit *fb)
{
    if (fb == NULL)
        return;

    SCFree(fb);

#ifdef FLOWBITS_STATS
    SCMutexLock(&flowbits_mutex);
    flowbits_removed++;
    if (flowbits_memuse >= sizeof(FlowBit))
        flowbits_memuse -= sizeof(FlowBit);
    else {
        printf("ERROR: flowbits memory usage going below 0!\n");
        flowbits_memuse = 0;
    }
    SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWBITS_STATS */
}


/* TESTS */
#ifdef UNITTESTS
static int FlowBitTest01 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);

    FlowBit *fb = FlowBitGet(&f,0);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest02 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBit *fb = FlowBitGet(&f,0);
    if (fb == NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest03 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);

    FlowBit *fb = FlowBitGet(&f,0);
    if (fb == NULL) {
        printf("fb == NULL although it was just added: ");
        goto end;
    }

    FlowBitRemove(&f, 0);

    fb = FlowBitGet(&f,0);
    if (fb != NULL) {
        printf("fb != NULL although it was just removed: ");
        goto end;
    } else {
        ret = 1;
    }
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest04 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,0);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest05 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,1);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest06 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,2);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest07 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,3);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest08 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,0);
    if (fb == NULL)
        goto end;

    FlowBitRemove(&f,0);

    fb = FlowBitGet(&f,0);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest09 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,1);
    if (fb == NULL)
        goto end;

    FlowBitRemove(&f,1);

    fb = FlowBitGet(&f,1);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest10 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,2);
    if (fb == NULL)
        goto end;

    FlowBitRemove(&f,2);

    fb = FlowBitGet(&f,2);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowBitTest11 (void)
{
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,3);
    if (fb == NULL)
        goto end;

    FlowBitRemove(&f,3);

    fb = FlowBitGet(&f,3);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

#endif /* UNITTESTS */

void FlowBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowBitTest01", FlowBitTest01, 1);
    UtRegisterTest("FlowBitTest02", FlowBitTest02, 1);
    UtRegisterTest("FlowBitTest03", FlowBitTest03, 1);
    UtRegisterTest("FlowBitTest04", FlowBitTest04, 1);
    UtRegisterTest("FlowBitTest05", FlowBitTest05, 1);
    UtRegisterTest("FlowBitTest06", FlowBitTest06, 1);
    UtRegisterTest("FlowBitTest07", FlowBitTest07, 1);
    UtRegisterTest("FlowBitTest08", FlowBitTest08, 1);
    UtRegisterTest("FlowBitTest09", FlowBitTest09, 1);
    UtRegisterTest("FlowBitTest10", FlowBitTest10, 1);
    UtRegisterTest("FlowBitTest11", FlowBitTest11, 1);
#endif /* UNITTESTS */
}

