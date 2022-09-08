/* Copyright (C) 2017-2021 Open Information Security Foundation
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
 * \defgroup applayerexpectation Application Layer Expectation
 *
 * Handling of dynamic parallel connection for application layer similar
 * to FTP.
 *
 * @{
 *
 * Some protocols like FTP create dynamic parallel flow (called expectation). In
 * order to assign a application layer protocol to these expectation, Suricata
 * needs to parse message of the initial protocol and create and maintain a list
 * of expected flow.
 *
 * Application layers must use the here described API to implement this mechanism.
 *
 * When parsing a application layer message describing a parallel flow, the
 * application layer can call AppLayerExpectationCreate() to declare an
 * expectation. By doing that the next flow coming with corresponding IP parameters
 * will be assigned the specified application layer. The resulting Flow will
 * also have a Flow storage set that can be retrieved at index
 * AppLayerExpectationGetDataId():
 *
 * ```
 * data = (char *)FlowGetStorageById(f, AppLayerExpectationGetFlowId());
 * ```
 * This storage can be used to store information that are only available in the
 * parent connection and could be useful in the parent connection. For instance
 * this is used by the FTP protocol to propagate information such as file name
 * and ftp operation to the FTP data connection.
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 */

#include "queue.h"
#include "suricata-common.h"
#include "debug.h"

#include "ippair-storage.h"
#include "flow-storage.h"

#include "app-layer-expectation.h"

#include "util-print.h"

static IPPairStorageId g_ippair_expectation_id = { .id = -1 };
static FlowStorageId g_flow_expectation_id = { .id = -1 };

SC_ATOMIC_DECLARE(uint32_t, expectation_count);

#define EXPECTATION_TIMEOUT 30
#define EXPECTATION_MAX_LEVEL 10

typedef struct Expectation_ {
    struct timeval ts;
    Port sp;
    Port dp;
    AppProto alproto;
    int direction;
    /* use pointer to Flow as identifier of the Flow the expectation is linked to */
    void *orig_f;
    void *data;
    CIRCLEQ_ENTRY(Expectation_) entries;
} Expectation;

typedef struct ExpectationData_ {
    /** Start of Expectation Data structure must be a pointer
     *  to free function. Set to NULL to use SCFree() */
    void (*DFree)(void *);
} ExpectationData;

typedef struct ExpectationList_ {
    CIRCLEQ_HEAD(EList, Expectation_) list;
    uint8_t length;
} ExpectationList;

static void ExpectationDataFree(void *e)
{
    SCLogDebug("Free expectation data");
    ExpectationData *ed = (ExpectationData *) e;
    if (ed->DFree) {
        ed->DFree(e);
    } else {
        SCFree(e);
    }
}

/**
 * Free expectation
 */
static void AppLayerFreeExpectation(Expectation *exp)
{
    if (exp->data) {
        ExpectationData *expdata = (ExpectationData *)exp->data;
        if (expdata->DFree) {
            expdata->DFree(exp->data);
        } else {
            SCFree(exp->data);
        }
    }
    SCFree(exp);
}

static void ExpectationListFree(void *el)
{
    ExpectationList *exp_list = (ExpectationList *)el;
    if (exp_list == NULL)
        return;

    if (exp_list->length > 0) {
        Expectation *exp = NULL, *pexp = NULL;
        CIRCLEQ_FOREACH_SAFE(exp, &exp_list->list, entries, pexp) {
            CIRCLEQ_REMOVE(&exp_list->list, exp, entries);
            exp_list->length--;
            AppLayerFreeExpectation(exp);
        }
    }
    SCFree(exp_list);
}

uint64_t ExpectationGetCounter(void)
{
    uint64_t x = SC_ATOMIC_GET(expectation_count);
    return x;
}

void AppLayerExpectationSetup(void)
{
    g_ippair_expectation_id =
            IPPairStorageRegister("expectation", sizeof(void *), NULL, ExpectationListFree);
    g_flow_expectation_id =
            FlowStorageRegister("expectation", sizeof(void *), NULL, ExpectationDataFree);
    SC_ATOMIC_INIT(expectation_count);
}

static ExpectationList *AppLayerExpectationLookup(Flow *f, IPPair **ipp)
{
    Address ip_src, ip_dst;
    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return NULL;
    *ipp = IPPairLookupIPPairFromHash(&ip_src, &ip_dst);
    if (*ipp == NULL) {
        return NULL;
    }

    return IPPairGetStorageById(*ipp, g_ippair_expectation_id);
}


static ExpectationList *AppLayerExpectationRemove(IPPair *ipp,
                                                  ExpectationList *exp_list,
                                                  Expectation *exp)
{
    CIRCLEQ_REMOVE(&exp_list->list, exp, entries);
    AppLayerFreeExpectation(exp);
    SC_ATOMIC_SUB(expectation_count, 1);
    exp_list->length--;
    if (exp_list->length == 0) {
        IPPairSetStorageById(ipp, g_ippair_expectation_id, NULL);
        ExpectationListFree(exp_list);
        exp_list = NULL;
    }
    return exp_list;
}

/**
 * Create an entry in expectation list
 *
 * Create a expectation from an existing Flow. Currently, only Flow between
 * the two original IP addresses are supported. In case of success, the
 * ownership of the data pointer is taken. In case of error, the pointer
 * to data has to be freed by the caller.
 *
 * \param f a pointer to the original Flow
 * \param direction the direction of the data in the expectation flow
 * \param src source port of the expected flow, use 0 for any
 * \param dst destination port of the expected flow, use 0 for any
 * \param alproto the protocol that need to be set on the expected flow
 * \param data pointer to data that will be attached to the expected flow
 *
 * \return -1 if error
 * \return 0 if success
 */
int AppLayerExpectationCreate(Flow *f, int direction, Port src, Port dst,
                              AppProto alproto, void *data)
{
    ExpectationList *exp_list = NULL;
    IPPair *ipp;
    Address ip_src, ip_dst;

    Expectation *exp = SCCalloc(1, sizeof(*exp));
    if (exp == NULL)
        return -1;

    exp->sp = src;
    exp->dp = dst;
    exp->alproto = alproto;
    exp->ts = f->lastts;
    exp->orig_f = (void *)f;
    exp->data = data;
    exp->direction = direction;

    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        goto error;
    ipp = IPPairGetIPPairFromHash(&ip_src, &ip_dst);
    if (ipp == NULL)
        goto error;

    exp_list = IPPairGetStorageById(ipp, g_ippair_expectation_id);
    if (exp_list) {
        CIRCLEQ_INSERT_HEAD(&exp_list->list, exp, entries);
        /* In case there is already EXPECTATION_MAX_LEVEL expectations waiting to be fullfill,
         * we remove the older expectation to limit the total number of expectations */
        if (exp_list->length >= EXPECTATION_MAX_LEVEL) {
            Expectation *last_exp = CIRCLEQ_LAST(&exp_list->list);
            CIRCLEQ_REMOVE(&exp_list->list, last_exp, entries);
            AppLayerFreeExpectation(last_exp);
            /* We keep the same amount of expectation so we fully release
             * the IP pair */
            f->flags |= FLOW_HAS_EXPECTATION;
            IPPairRelease(ipp);
            return 0;
        }
    } else {
        exp_list = SCCalloc(1, sizeof(*exp_list));
        if (exp_list == NULL)
            goto error;
        exp_list->length = 0;
        CIRCLEQ_INIT(&exp_list->list);
        CIRCLEQ_INSERT_HEAD(&exp_list->list, exp, entries);
        IPPairSetStorageById(ipp, g_ippair_expectation_id, exp_list);
    }

    exp_list->length += 1;
    SC_ATOMIC_ADD(expectation_count, 1);
    f->flags |= FLOW_HAS_EXPECTATION;
    /* As we are creating the expectation, we release lock on IPPair without
     * setting the ref count to 0. This way the IPPair will be kept till
     * cleanup */
    IPPairUnlock(ipp);
    return 0;

error:
    SCFree(exp);
    return -1;
}

/**
 * Return Flow storage identifier corresponding to expectation data
 *
 * \return expectation data identifier
 */
FlowStorageId AppLayerExpectationGetFlowId(void)
{
    return g_flow_expectation_id;
}

/**
 * Function doing a lookup in expectation list and updating Flow if needed.
 *
 * This function lookup for a existing expectation that could match the Flow.
 * If found and if the expectation contains data it store the data in the
 * expectation storage of the Flow.
 *
 * \return an AppProto value if found
 * \return ALPROTO_UNKNOWN if not found
 */
AppProto AppLayerExpectationHandle(Flow *f, uint8_t flags)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    IPPair *ipp = NULL;
    Expectation *lexp = NULL;
    Expectation *exp = NULL;

    int x = SC_ATOMIC_GET(expectation_count);
    if (x == 0) {
        return ALPROTO_UNKNOWN;
    }

    /* Call will take reference of the ip pair in 'ipp' */
    ExpectationList *exp_list = AppLayerExpectationLookup(f, &ipp);
    if (exp_list == NULL)
        goto out;

    time_t ctime = f->lastts.tv_sec;

    CIRCLEQ_FOREACH_SAFE(exp, &exp_list->list, entries, lexp) {
        if ((exp->direction & flags) && ((exp->sp == 0) || (exp->sp == f->sp)) &&
                ((exp->dp == 0) || (exp->dp == f->dp))) {
            alproto = exp->alproto;
            if (f->alproto_ts == ALPROTO_UNKNOWN) {
                f->alproto_ts = alproto;
            }
            if (f->alproto_tc == ALPROTO_UNKNOWN) {
                f->alproto_tc = alproto;
            }
            void *fdata = FlowGetStorageById(f, g_flow_expectation_id);
            if (fdata) {
                /* We already have an expectation so let's clean this one */
                ExpectationDataFree(exp->data);
            } else {
                /* Transfer ownership of Expectation data to the Flow */
                if (FlowSetStorageById(f, g_flow_expectation_id, exp->data) != 0) {
                    SCLogDebug("Unable to set flow storage");
                }
            }
            exp->data = NULL;
            exp_list = AppLayerExpectationRemove(ipp, exp_list, exp);
            if (exp_list == NULL)
                goto out;
            continue;
        }
        /* Cleaning remove old entries */
        if (ctime > exp->ts.tv_sec + EXPECTATION_TIMEOUT) {
            exp_list = AppLayerExpectationRemove(ipp, exp_list, exp);
            if (exp_list == NULL)
                goto out;
            continue;
        }
    }

out:
    if (ipp)
        IPPairRelease(ipp);
    return alproto;
}

void AppLayerExpectationClean(Flow *f)
{
    IPPair *ipp = NULL;
    Expectation *exp = NULL;
    Expectation *pexp = NULL;

    int x = SC_ATOMIC_GET(expectation_count);
    if (x == 0) {
        return;
    }

    /* Call will take reference of the ip pair in 'ipp' */
    ExpectationList *exp_list = AppLayerExpectationLookup(f, &ipp);
    if (exp_list == NULL)
        goto out;

    CIRCLEQ_FOREACH_SAFE(exp, &exp_list->list, entries, pexp) {
        /* Cleaning remove old entries */
        if (exp->orig_f == (void *)f) {
            exp_list = AppLayerExpectationRemove(ipp, exp_list, exp);
            if (exp_list == NULL)
                goto out;
        }
    }

out:
    if (ipp)
        IPPairRelease(ipp);
    return;
}

/**
 * @}
 */
