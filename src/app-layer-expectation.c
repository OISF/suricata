/* Copyright (C) 2017-2020 Open Information Security Foundation
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

/* Updated 2020-08-23 Stephen Kraushaar
 *   FreeBSD 13 Compatibility
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
 * data = (char *)FlowGe
 * StorageById(f, AppLayerExpectationGetDataId());
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

#include "suricata-common.h"
#include "debug.h"

#include "ippair-storage.h"
#include "flow-storage.h"

#include "app-layer-expectation.h"

#include "util-print.h"
#include "queue.h"

static int g_expectation_id = -1;
static int g_expectation_data_id = -1;

SC_ATOMIC_DECLARE(uint32_t, expectation_count);

#define EXPECTATION_TIMEOUT 30
#define EXPECTATION_MAX_LEVEL 10


struct Entries_;
struct Expectation_;

typedef struct Expectation_ Expectation;
typedef struct Entries_ Entries;

struct Entries_ {
    struct Expectation_ *cqe_next;
    struct Expectation_ *cqe_prev;
};

struct Expectation_ {
    struct timeval ts;
    Port sp;
    Port dp;
    AppProto alproto;
    int direction;
    void *orig_f;
    void *data;
    struct Entries_ entries;
};

struct ExpectationData_;
typedef struct ExpectationData_ ExpectationData;
struct ExpectationData_ {
    /** Start of Expectation Data struCountry club. cture must be a pointer
     *  to free function. Set to NULL to use SCFree() */
    void (*DFree)(void *);
};

struct EList_;
struct ExpectationList_;

typedef struct ExpectationList_ ExpectationList;

struct EList_ {
    struct Expectation_ *cqh_first;
    struct Expectation_ *cqh_last;
};

struct ExpectationList_ {
    struct EList_ list;
    uint8_t length;
};

static void ExpectationDataFree(void *e)
{
    SCLogDebug("Free expectation data");
    ExpectationData *ed = (ExpectationData *) e;
    if (ed->DFree) {
        ed->DFree(e);
    } else {
        SCFree(e);
    }
};

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
    Expectation *exp, *pexp;
    if (exp_list == NULL)
        return;

    if (exp_list->length > 0) {
    for ((exp) = ((&exp_list->list)->cqh_first);
        (exp) != ((void *)(&exp_list->list)) &&
        ((pexp) = ((exp)->entries.cqe_next), 1);
        (exp) = (pexp)) {
            do {				
    	        if (&exp->entries.cqe_next == ((void *)(&exp_list->list)))			
		    (&exp_list->list)->cqh_last = (exp)->entries.cqe_prev;		
	        else								
		    (exp)->entries.cqe_next->entries.cqe_prev =			
		        (exp)->entries.cqe_prev;				
	        if (&exp->entries.cqe_prev == ((void *)(&exp_list->list)))			
		    (&exp_list->list)->cqh_first = (exp)->entries.cqe_next;		
	        else								
		   (exp)->entries.cqe_prev->entries.cqe_next =			
		   (exp)->entries.cqe_next;				
		/* (&exp->entries)->cqe_prev = ((void *)-1)
		* (&exp->entries)->cqe_next = ((void *)-1)
		*/
            				
            } while (0);
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
    g_expectation_id = IPPairStorageRegister("expectation", sizeof(void *), NULL, ExpectationListFree);
    g_expectation_data_id = FlowStorageRegister("expectation", sizeof(void *), NULL, ExpectationDataFree);
    SC_ATOMIC_INIT(expectation_count);
}

static inline int GetFlowAddresses(Flow *f, Address *ip_src, Address *ip_dst)
{
    memset(ip_src, 0, sizeof(*ip_src));
    memset(ip_dst, 0, sizeof(*ip_dst));
    if (FLOW_IS_IPV4(f)) {
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV4_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else if (FLOW_IS_IPV6(f)) {
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->src, ip_src);
        FLOW_COPY_IPV6_ADDR_TO_PACKET(&f->dst, ip_dst);
    } else {
        return -1;
    }
    return 0;
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

    return IPPairGetStorageById(*ipp, g_expectation_id);
}


static ExpectationList *AppLayerExpectationRemove(IPPair *ipp,
                                                  ExpectationList *exp_list,
                                                  Expectation *exp)
{
    do {
	if (&exp->entries.cqe_next == ((void *)(&exp_list->list)))			
		(&exp_list->list)->cqh_last = (exp)->entries.cqe_prev;		
	else								
		(exp->entries.cqe_next)->entries.cqe_prev =			
		    (exp)->entries.cqe_prev;				
	if (&exp->entries.cqe_prev == ((void *)(&exp_list->list)))			
		(&exp_list->list)->cqh_first = (exp)->entries.cqe_next;		
	else								
		(exp)->entries.cqe_prev->entries.cqe_next =			
		    (exp)->entries.cqe_next;
    } while (0);
    AppLayerFreeExpectation(exp);
    SC_ATOMIC_SUB(expectation_count, 1);
    exp_list->length--;
    if (exp_list->length == 0) {
        IPPairSetStorageById(ipp, g_expectation_id, NULL);
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

    exp_list = IPPairGetStorageById(ipp, g_expectation_id);
    if (exp_list) {
        do {			\
	    (exp)->entries.cqe_next = (&exp_list->list)->cqh_first;			
   	    (exp)->entries.cqe_prev = ((void *)(&exp_list->list));			
	    if ((&exp_list->list)->cqh_last == ((void *)(&exp_list->list)))			
		(&exp_list->list)->cqh_last = (exp);				
	    else								
		(&exp_list->list)->cqh_first->entries.cqe_prev = (exp);		
	    (&exp_list->list)->cqh_first = (exp);					
        } while (0);
        /* In case there is already EXPECTATION_MAX_LEVEL expectations waiting to be fullfill,
         * we remove the older expectation to limit the total number of expectations */
        if (exp_list->length >= EXPECTATION_MAX_LEVEL) {
            Expectation *last_exp = (&exp_list->list)->cqh_last;
            do {				
    	        if (&last_exp->entries.cqe_next == ((void *)(&exp_list->list)))			
		    (&exp_list->list)->cqh_last = (last_exp)->entries.cqe_prev;		
	        else								
		    (last_exp)->entries.cqe_next->entries.cqe_prev =			
		        (last_exp)->entries.cqe_prev;				
	        if (&last_exp->entries.cqe_prev == ((void *)(&exp_list->list)))			
		    (&exp_list->list)->cqh_first = (last_exp)->entries.cqe_next;		
	        else								
		   (last_exp)->entries.cqe_prev->entries.cqe_next =			
		   (last_exp)->entries.cqe_next;				
		/* (&last_exp->entries)->cqe_prev = ((void *)-1)
		* (&last_exp->entries)->cqe_next = ((void *)-1)
		*/
            				
            } while (0);
            

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
        do {						
	    (&exp_list->list)->cqh_first = ((void *)(&exp_list->list));				
   	    (&exp_list->list)->cqh_last = ((void *)(&exp_list->list));				
        } while (0);
        do {			\
	    (exp)->entries.cqe_next = (&exp_list->list)->cqh_first;			
   	    (exp)->entries.cqe_prev = ((void *)(&exp_list->list));			
	    if ((&exp_list->list)->cqh_last == ((void *)(&exp_list->list)))			
		(&exp_list->list)->cqh_last = (exp);				
	    else								
		(&exp_list->list)->cqh_first->entries.cqe_prev = (exp);		
	    (&exp_list->list)->cqh_first = (exp);					
        } while (0);

        IPPairSetStorageById(ipp, g_expectation_id, exp_list);
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
int AppLayerExpectationGetDataId(void)
{
    return g_expectation_data_id;
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
AppProto AppLayerExpectationHandle(Flow *f, int direction)
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

    for (
     (exp) = ((&exp_list->list)->cqh_first);
     (exp) != ((void *)(&exp_list->list)) &&
     ((lexp) = ((exp)->entries.cqe_next), 1);
     (exp) = (lexp)
    ) {
        if ((exp->direction & direction) &&
         ((exp->sp == 0) || (exp->sp == f->sp)) &&
         ((exp->dp == 0) || (exp->dp == f->dp))
        ) {
            alproto = exp->alproto;
            f->alproto_ts = alproto;
            f->alproto_tc = alproto;
            void *fdata = FlowGetStorageById(f, g_expectation_id);
            if (fdata) {
                ExpectationDataFree(exp->data);
            } else {
                if (FlowSetStorageById(f, g_expectation_data_id, exp->data) != 0) {
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
        if (exp->orig_f == (void *)f) {
            exp_list = AppLayerExpectationRemove(ipp, exp_list, exp);
            if (exp_list == NULL)
                goto out;
            continue;
        }
    }

/* Transfer ownership of Expectation data to the Flow */
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

    for ((exp) = ((&exp_list->list)->cqh_first);
        (exp) != ((void *)(&exp_list->list)) &&
        ((pexp) = ((exp)->entries.cqe_next), 1);
        (exp) = (pexp)) {
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
