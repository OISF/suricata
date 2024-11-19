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
static FlowBit *FlowBitGet(Flow *f, uint32_t idx)
{
    GenericVar *gv = f->flowvar;
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWBITS && gv->idx == idx) {
            return (FlowBit *)gv;
        }
    }

    return NULL;
}

/** \brief add a flowbit to the flow
 *  \retval -1 error
 *  \retval 0 not added, already set before
 *  \retval 1 added */
static int FlowBitAdd(Flow *f, uint32_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(FlowBit));
        if (unlikely(fb == NULL))
            return -1;

        fb->type = DETECT_FLOWBITS;
        fb->idx = idx;
        fb->next = NULL;
        GenericVarAppend(&f->flowvar, (GenericVar *)fb);
        return 1;
    } else {
        return 0;
    }
}

static void FlowBitRemove(Flow *f, uint32_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL)
        return;

    GenericVarRemove(&f->flowvar, (GenericVar *)fb);
    FlowBitFree(fb);
}

/** \brief add a flowbit to the flow
 *  \retval -1 error
 *  \retval 0 not added, already set before
 *  \retval 1 added */
int FlowBitSet(Flow *f, uint32_t idx)
{
    return FlowBitAdd(f, idx);
}

void FlowBitUnset(Flow *f, uint32_t idx)
{
    FlowBitRemove(f, idx);
}

/**
 * \retval bool true if bit is set, false is unset
 */
bool FlowBitToggle(Flow *f, uint32_t idx)
{
    FlowBit *fb = FlowBitGet(f, idx);
    if (fb != NULL) {
        FlowBitRemove(f, idx);
        return false;
    } else {
        FlowBitAdd(f, idx);
        return true;
    }
}

int FlowBitIsset(Flow *f, uint32_t idx)
{
    int r = 0;

    FlowBit *fb = FlowBitGet(f, idx);
    if (fb != NULL) {
        r = 1;
    }

    return r;
}

int FlowBitIsnotset(Flow *f, uint32_t idx)
{
    int r = 0;

    FlowBit *fb = FlowBitGet(f, idx);
    if (fb == NULL) {
        r = 1;
    }

    return r;
}

void FlowBitFree(FlowBit *fb)
{
    if (fb == NULL)
        return;

    SCFree(fb);
}


/* TESTS */
#ifdef UNITTESTS
static int FlowBitTest01 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);

    FlowBit *fb = FlowBitGet(&f, 0);
    FAIL_IF_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest02 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBit *fb = FlowBitGet(&f, 0);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest03 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);

    FlowBit *fb = FlowBitGet(&f,0);
    FAIL_IF_NULL(fb);

    FlowBitRemove(&f, 0);

    fb = FlowBitGet(&f, 0);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest04 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f, 0);
    FAIL_IF_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest05 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f, 1);
    FAIL_IF_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest06 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f, 2);
    FAIL_IF_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest07 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f, 3);
    FAIL_IF_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest08 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,0);
    FAIL_IF_NULL(fb);

    FlowBitRemove(&f,0);

    fb = FlowBitGet(&f, 0);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest09 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,1);
    FAIL_IF_NULL(fb);

    FlowBitRemove(&f,1);

    fb = FlowBitGet(&f, 1);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest10 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,2);
    FAIL_IF_NULL(fb);

    FlowBitRemove(&f,2);

    fb = FlowBitGet(&f, 2);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

static int FlowBitTest11 (void)
{
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowBitAdd(&f, 0);
    FlowBitAdd(&f, 1);
    FlowBitAdd(&f, 2);
    FlowBitAdd(&f, 3);

    FlowBit *fb = FlowBitGet(&f,3);
    FAIL_IF_NULL(fb);

    FlowBitRemove(&f,3);

    fb = FlowBitGet(&f, 3);
    FAIL_IF_NOT_NULL(fb);

    GenericVarFree(f.flowvar);
    PASS;
}

#endif /* UNITTESTS */

void FlowBitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FlowBitTest01", FlowBitTest01);
    UtRegisterTest("FlowBitTest02", FlowBitTest02);
    UtRegisterTest("FlowBitTest03", FlowBitTest03);
    UtRegisterTest("FlowBitTest04", FlowBitTest04);
    UtRegisterTest("FlowBitTest05", FlowBitTest05);
    UtRegisterTest("FlowBitTest06", FlowBitTest06);
    UtRegisterTest("FlowBitTest07", FlowBitTest07);
    UtRegisterTest("FlowBitTest08", FlowBitTest08);
    UtRegisterTest("FlowBitTest09", FlowBitTest09);
    UtRegisterTest("FlowBitTest10", FlowBitTest10);
    UtRegisterTest("FlowBitTest11", FlowBitTest11);
#endif /* UNITTESTS */
}

