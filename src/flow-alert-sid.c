/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "flow-alert-sid.h"
#include "flow.h"
#include "flow-util.h"
#include "flow-private.h"
#include "detect.h"
#include "util-var.h"
#include "util-unittest.h"
#include "util-debug.h"

/* get the flowbit with idx from the flow */
static FlowAlertSid *FlowAlertSidGet(Flow *f, uint32_t sid) {
    GenericVar *gv = f->flowvar;
    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_FLOWALERTSID) {
            FlowAlertSid *fas = (FlowAlertSid *)gv;

            SCLogDebug("fas->type %"PRIu32", fas->sid %"PRIu32"", fas->type, fas->sid);
            if (fas->sid == sid) {
                return (FlowAlertSid *)gv;
            }
        }
    }

    return NULL;
}

/* add a flowbit to the flow */
static void FlowAlertSidAdd(Flow *f, uint32_t sid) {
    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb == NULL) {
        fb = SCMalloc(sizeof(FlowAlertSid));
        if (unlikely(fb == NULL))
            return;

        fb->type = DETECT_FLOWALERTSID;
        fb->sid = sid;
        fb->next = NULL;

        SCLogDebug("fb->type %u, sid %"PRIu32"", fb->type, fb->sid);
        GenericVarAppend(&f->flowvar, (GenericVar *)fb);
        SCLogDebug("fb->type %u, sid %"PRIu32"", fb->type, fb->sid);

        SCLogDebug("adding flowalertsid with sid %" PRIu32 " (%"PRIu32")", sid, fb->sid);
#ifdef FLOWALERTSID_STATS
        SCMutexLock(&flowbits_mutex);
        flowbits_added++;
        flowbits_memuse += sizeof(FlowAlertSid);
        if (flowbits_memuse > flowbits_memuse_max)
            flowbits_memuse_max = flowbits_memuse;
        SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWALERTSID_STATS */
    }
}

static void FlowAlertSidRemove(Flow *f, uint32_t sid) {
    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb == NULL)
        return;

    GenericVarRemove(&f->flowvar, (GenericVar *)fb);

    //printf("FlowAlertSidRemove: remove flowbit with idx %" PRIu32 "\n", idx);
#ifdef FLOWALERTSID_STATS
    SCMutexLock(&flowbits_mutex);
    flowbits_removed++;
    if (flowbits_memuse >= sizeof(FlowAlertSid))
        flowbits_memuse -= sizeof(FlowAlertSid);
    else {
        printf("ERROR: flowbits memory usage going below 0!\n");
        flowbits_memuse = 0;
    }
    SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWALERTSID_STATS */
}

void FlowAlertSidSet(Flow *f, uint32_t sid) {
    FLOWLOCK_WRLOCK(f);

    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb == NULL) {
        FlowAlertSidAdd(f, sid);
    }

    FLOWLOCK_UNLOCK(f);
}

void FlowAlertSidUnset(Flow *f, uint32_t sid) {
    FLOWLOCK_WRLOCK(f);

    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb != NULL) {
        FlowAlertSidRemove(f, sid);
    }

    FLOWLOCK_UNLOCK(f);
}

void FlowAlertSidToggle(Flow *f, uint32_t sid) {
    FLOWLOCK_WRLOCK(f);

    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb != NULL) {
        FlowAlertSidRemove(f, sid);
    } else {
        FlowAlertSidAdd(f, sid);
    }

    FLOWLOCK_UNLOCK(f);
}

int FlowAlertSidIsset(Flow *f, uint32_t sid) {
    int r = 0;
    FLOWLOCK_RDLOCK(f);

    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb != NULL) {
        r = 1;
    }

    FLOWLOCK_UNLOCK(f);
    return r;
}

int FlowAlertSidIsnotset(Flow *f, uint32_t sid) {
    int r = 0;
    FLOWLOCK_RDLOCK(f);

    FlowAlertSid *fb = FlowAlertSidGet(f, sid);
    if (fb == NULL) {
        r = 1;
    }

    FLOWLOCK_UNLOCK(f);
    return r;
}

void FlowAlertSidFree(FlowAlertSid *fb) {
    if (fb == NULL)
        return;

    SCFree(fb);

#ifdef FLOWALERTSID_STATS
    SCMutexLock(&flowbits_mutex);
    flowbits_removed++;
    if (flowbits_memuse >= sizeof(FlowAlertSid))
        flowbits_memuse -= sizeof(FlowAlertSid);
    else {
        printf("ERROR: flowbits memory usage going below 0!\n");
        flowbits_memuse = 0;
    }
    SCMutexUnlock(&flowbits_mutex);
#endif /* FLOWALERTSID_STATS */
}


/* TESTS */
#ifdef UNITTESTS
static int FlowAlertSidTest01 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);

    FlowAlertSid *fb = FlowAlertSidGet(&f,0);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest02 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSid *fb = FlowAlertSidGet(&f,0);
    if (fb == NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest03 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);

    FlowAlertSid *fb = FlowAlertSidGet(&f,0);
    if (fb == NULL) {
        printf("fb == NULL although it was just added: ");
        goto end;
    }

    FlowAlertSidRemove(&f, 0);

    fb = FlowAlertSidGet(&f,0);
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

static int FlowAlertSidTest04 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,0);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest05 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,1);
    if (fb == NULL) {
        printf("fb == NULL: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest06 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,2);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest07 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,3);
    if (fb != NULL)
        ret = 1;

    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest08 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,0);
    if (fb == NULL)
        goto end;

    FlowAlertSidRemove(&f,0);

    fb = FlowAlertSidGet(&f,0);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest09 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,1);
    if (fb == NULL)
        goto end;

    FlowAlertSidRemove(&f,1);

    fb = FlowAlertSidGet(&f,1);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest10 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,2);
    if (fb == NULL)
        goto end;

    FlowAlertSidRemove(&f,2);

    fb = FlowAlertSidGet(&f,2);
    if (fb != NULL) {
        printf("fb != NULL even though it was removed: ");
        goto end;
    }

    ret = 1;
end:
    GenericVarFree(f.flowvar);
    return ret;
}

static int FlowAlertSidTest11 (void) {
    int ret = 0;

    Flow f;
    memset(&f, 0, sizeof(Flow));

    FlowAlertSidAdd(&f, 0);
    FlowAlertSidAdd(&f, 1);
    FlowAlertSidAdd(&f, 2);
    FlowAlertSidAdd(&f, 3);

    FlowAlertSid *fb = FlowAlertSidGet(&f,3);
    if (fb == NULL)
        goto end;

    FlowAlertSidRemove(&f,3);

    fb = FlowAlertSidGet(&f,3);
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

void FlowAlertSidRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("FlowAlertSidTest01", FlowAlertSidTest01, 1);
    UtRegisterTest("FlowAlertSidTest02", FlowAlertSidTest02, 1);
    UtRegisterTest("FlowAlertSidTest03", FlowAlertSidTest03, 1);
    UtRegisterTest("FlowAlertSidTest04", FlowAlertSidTest04, 1);
    UtRegisterTest("FlowAlertSidTest05", FlowAlertSidTest05, 1);
    UtRegisterTest("FlowAlertSidTest06", FlowAlertSidTest06, 1);
    UtRegisterTest("FlowAlertSidTest07", FlowAlertSidTest07, 1);
    UtRegisterTest("FlowAlertSidTest08", FlowAlertSidTest08, 1);
    UtRegisterTest("FlowAlertSidTest09", FlowAlertSidTest09, 1);
    UtRegisterTest("FlowAlertSidTest10", FlowAlertSidTest10, 1);
    UtRegisterTest("FlowAlertSidTest11", FlowAlertSidTest11, 1);
#endif /* UNITTESTS */
}

