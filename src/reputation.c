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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *         Original Idea by Matt Jonkman
 *
 * IP Reputation Module, initial API for IPV4 and IPV6 feed
 */

#include "util-error.h"
#include "util-debug.h"
#include "util-radix-tree.h"
#include "reputation.h"
#include "util-host-os-info.h"
#include "util-unittest.h"
#include "suricata-common.h"
#include "threads.h"

/** Global trees that hold host reputation for IPV4 and IPV6 hosts */
IPReputationCtx *rep_ctx;

/**
 * \brief Initialization fuction for the Reputation Context (IPV4 and IPV6)
 *
 * \retval Pointer to the IPReputationCtx created
 *         NULL Error initializing moule;
 */
IPReputationCtx *SCReputationInitCtx() {
    rep_ctx = (IPReputationCtx *)SCMalloc(sizeof(IPReputationCtx));
    if (rep_ctx == NULL)
        return NULL;
    memset(rep_ctx,0,sizeof(IPReputationCtx));

    rep_ctx->reputationIPV4_tree = SCRadixCreateRadixTree(SCReputationFreeData, NULL);
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogDebug("Error initializing Reputation IPV4 module");
        return NULL;
    }

    SCLogDebug("Reputation IPV4 module initialized");

    rep_ctx->reputationIPV6_tree = SCRadixCreateRadixTree(SCReputationFreeData, NULL);
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogDebug("Error initializing Reputation IPV6 module");
        return NULL;
    }

    SCLogDebug("Reputation IPV6 module initialized");
    if (SCMutexInit(&rep_ctx->reputationIPV4_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
        exit(EXIT_FAILURE);
    }
    if (SCMutexInit(&rep_ctx->reputationIPV6_lock, NULL) != 0) {
        SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
        exit(EXIT_FAILURE);
    }

    return rep_ctx;
}


/**
 * \brief Allocates the Reputation structure for a host/netblock
 *
 * \retval rep_data On success, pointer to the rep_data that has to be sent
 *                   along with the key, to be added to the Radix tree
 */
Reputation *SCReputationAllocData()
{
    Reputation *rep_data = NULL;

    if ( (rep_data = SCMalloc(sizeof(Reputation))) == NULL)
        return NULL;
    memset(rep_data,0, sizeof(Reputation));
    rep_data->ctime = time(NULL);
    rep_data->mtime= time(NULL);

    return rep_data;
}

/**
 * \brief Used to SCFree the reputation data that is allocated by Reputation API
 *
 * \param Pointer to the data that has to be SCFreed
 */
void SCReputationFreeData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

/**
 * \brief Allocates the Reputation structure for a host/netblock
 *
 * \retval ReputationTransaction pointer On success
 */
ReputationTransaction *SCReputationTransactionAlloc()
{
    ReputationTransaction *rtx = NULL;

    if ( (rtx = SCMalloc(sizeof(ReputationTransaction))) == NULL)
        return NULL;
    memset(rtx, 0, sizeof(ReputationTransaction));

    return rtx;
}

/**
 * \brief Used to SCFree the transaction data
 *
 * \param Pointer to the data that has to be SCFreed
 */
void SCReputationTransactionFreeData(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

/**
 * \brief Apply the transaction of changes to the reputation
 *        We use transactions because we cant be locking/unlocking the
 *        trees foreach update. This help for a better performance
 *
 * \param rep_data pointer to the reputation to update
 * \param rtx pointer to the transaction data
 */
void SCReputationApplyTransaction(Reputation *rep_data, ReputationTransaction *rtx) {
    int i = 0;

    /* No modification needed */
    if ( !(rtx->flags & TRANSACTION_FLAG_NEEDSYNC))
        return;

    /* Here we should apply a formula, a threshold or similar,
     * maybe values loaded from config */
    for (; i < REPUTATION_NUMBER; i++) {
        if (rtx->flags & TRANSACTION_FLAG_INCS) {
            if (rep_data->reps[i] + rtx->inc[i] < 255)
                rep_data->reps[i] += rtx->inc[i];
            else
                rep_data->reps[i] = 255;
        }
        if (rtx->flags & TRANSACTION_FLAG_DECS) {
            if (rep_data->reps[i] - rtx->dec[i] > 0)
                rep_data->reps[i] -= rtx->dec[i];
            else
                rep_data->reps[i] = 0;
        }
    }
    rep_data->mtime = time(NULL);
    rep_data->flags |= REPUTATION_FLAG_NEEDSYNC;
}

/**
 * \brief Function that compare two reputation structs to determine if they are equal
 *
 * \param rep1 pointer to reputation 1
 * \param rep2 pointer to reputation 2
 *
 * \retval 1 if they are equal; 0 if not
 */
int SCReputationEqual(Reputation *rep1, Reputation *rep2)
{
    return (memcmp(rep1->reps, rep2->reps, REPUTATION_NUMBER * sizeof(uint8_t)) == 0)? 1 : 0;
}


/**
 * \brief Helper function to print the Reputation structure
 *
 * \param Pointer rep_data to a Reputation structure
 */
void SCReputationPrint(Reputation *rep_data)
{
    if (rep_data == NULL) {
        printf("No Reputation Data!\n");
        return;
    }
    int i = 0;
    for (; i < REPUTATION_NUMBER; i++)
        printf("Rep_type %d = %d\n", i, rep_data->reps[i]);

    if (rep_data->flags & REPUTATION_FLAG_NEEDSYNC)
        printf("REPUTATION_FLAG_NEEDSYNC = 1\n");
}

/**
 * \brief Clone all the data of a reputation
 *        When you try to update the feed, if the data you have belongs
 *        to a netblock, it will be cloned and inserted or a host, with
 *        the modifications that you add
 *
 * \param orig Pointer to the original reputation (probably of a netblock)
 *
 * \retval Reputation Pointer to the reputation copy
 */
Reputation *SCReputationClone(Reputation *orig)
{
    Reputation *rep = NULL;
    if (orig == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    if ( (rep = SCMalloc(sizeof(Reputation))) == NULL)
        return NULL;
    memcpy(rep, orig, sizeof(Reputation));
    return rep;
}

void SCReputationFreeCtx()
{
    if (rep_ctx->reputationIPV4_tree != NULL) {
        SCRadixReleaseRadixTree(rep_ctx->reputationIPV4_tree);
        rep_ctx->reputationIPV4_tree = NULL;
        SCMutexDestroy(&rep_ctx->reputationIPV4_lock);
    }
    if (rep_ctx->reputationIPV6_tree != NULL) {
        SCRadixReleaseRadixTree(rep_ctx->reputationIPV6_tree);
        rep_ctx->reputationIPV6_tree = NULL;
        SCMutexDestroy(&rep_ctx->reputationIPV6_lock);
    }
}

/**
 * \brief Used to add a new reputation to the reputation module (only at the startup)
 *
 * \param ipv4addr pointer to the ipv4 address key
 * \param netmask_value of the ipv4 address (can be a subnet or a host (32))
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure; rep_data on success
 */
Reputation *SCReputationAddIPV4Data(uint8_t *ipv4addr, int netmask_value, Reputation *rep_data)
{
    struct in_addr *ipv4_addr = (struct in_addr *) ipv4addr;

    if (ipv4_addr == NULL || rep_data == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    if (netmask_value == 32) {
        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV4_lock);
        SCRadixAddKeyIPV4((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
                  (void *)rep_data);
        SCMutexUnlock(&rep_ctx->reputationIPV4_lock);

    } else {
        if (netmask_value < 0 || netmask_value > 31) {
            SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "Invalid IPV4 Netblock");
            return NULL;
        }

        SCRadixChopIPAddressAgainstNetmask((uint8_t *)ipv4_addr, netmask_value, 32);

        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV4_lock);
        SCRadixAddKeyIPV4Netblock((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
                      (void *)rep_data, netmask_value);
        SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    }

    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (exact match), given an ipv4 address in the raw
 *        address format.
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4ExactMatch(uint8_t *ipv4_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    SCRadixNode *node = SCRadixFindKeyIPV4ExactMatch(ipv4_addr, rep_ctx->reputationIPV4_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)node->prefix->user_data_result);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (best match), given an ipv4 address in the raw
 *        address format.
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4BestMatch(uint8_t *ipv4_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(ipv4_addr, rep_ctx->reputationIPV4_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)node->prefix->user_data_result);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (best match), given an ipv6 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to a copy of the host Reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6BestMatch(uint8_t *ipv6_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    SCRadixNode *node = SCRadixFindKeyIPV6BestMatch(ipv6_addr, rep_ctx->reputationIPV6_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)node->prefix->user_data_result);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    return rep_data;
}

/**
 * \brief Retrieves the Reputation of a host (exact match), given an ipv6 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to a copy of the host reputation on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6ExactMatch(uint8_t *ipv6_addr)
{
    Reputation *rep_data;

    /* Be careful with this (locking)*/
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    SCRadixNode *node = SCRadixFindKeyIPV6ExactMatch(ipv6_addr, rep_ctx->reputationIPV6_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        rep_data = NULL;
    } else {
        /* Yes, we clone it because the pointer can be outdated
         * while another thread remove this reputation */
        rep_data = SCReputationClone((Reputation *)node->prefix->user_data_result);
    }

    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    return rep_data;
}


/**
 * \brief Retrieves the Real Reputation of a host (exact match), given an ipv4 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4ExactMatchReal(uint8_t *ipv4_addr)
{
    SCRadixNode *node = SCRadixFindKeyIPV4ExactMatch(ipv4_addr, rep_ctx->reputationIPV4_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        return NULL;
    } else {
        return (Reputation *)node->prefix->user_data_result;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (best match), given an ipv4 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param ipv4_addr Pointer to a raw ipv4 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV4BestMatchReal(uint8_t *ipv4_addr)
{
    SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(ipv4_addr, rep_ctx->reputationIPV4_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        return NULL;
    } else {
        return (Reputation *)node->prefix->user_data_result;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (best match), given an ipv6 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6BestMatchReal(uint8_t *ipv6_addr)
{
    SCRadixNode *node = SCRadixFindKeyIPV6BestMatch(ipv6_addr, rep_ctx->reputationIPV6_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        return NULL;
    } else {
        return (Reputation *)node->prefix->user_data_result;
    }
}

/**
 * \brief Retrieves the Real Reputation of a host (exact match), given an ipv6 address in the raw
 *        address format. (Not thread safe!)
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval Pointer to the Reputation of the host on success;
 *                 NULL on failure, or on not finding the key;
 */
Reputation *SCReputationLookupIPV6ExactMatchReal(uint8_t *ipv6_addr)
{
    SCRadixNode *node = SCRadixFindKeyIPV6ExactMatch(ipv6_addr, rep_ctx->reputationIPV6_tree);
    if (node == NULL || node->prefix == NULL || node->prefix->user_data_result == NULL) {
        return NULL;
    } else {
        return (Reputation *)node->prefix->user_data_result;
    }
}

/**
 * \brief Remove the node of the reputation tree associated to the ipv4 address
 *
 * \param ipv4_addr Pointer to a raw ipv4 address
 * \param netmask_value netmask to apply to the address (32 for host)
 *
 */
void SCReputationRemoveIPV4Data(uint8_t * ipv4_addr, uint8_t netmask_value)
{
    SCMutexLock(&rep_ctx->reputationIPV4_lock);
    SCRadixRemoveKeyIPV4Netblock(ipv4_addr, rep_ctx->reputationIPV4_tree, netmask_value);
    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);
}

/**
 * \brief Remove the node of the reputation tree associated to the ipv6 address
 *
 * \param ipv6_addr Pointer to a raw ipv6 address
 * \param netmask_value netmask to apply to the address (128 for host)
 *
 */
void SCReputationRemoveIPV6Data(uint8_t * ipv6_addr, uint8_t netmask_value)
{
    SCMutexLock(&rep_ctx->reputationIPV6_lock);
    SCRadixRemoveKeyIPV6Netblock(ipv6_addr, rep_ctx->reputationIPV6_tree, netmask_value);
    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
}

/**
 * \brief Used to add a new reputation to the reputation module (only at the startup)
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param netmask_value of the ipv6 address (can be a subnet)
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationAddIPV6Data(uint8_t *ipv6addr, int netmask_value, Reputation *rep_data)
{
    struct in_addr *ipv6_addr = (struct in_addr *) ipv6addr;

    if (ipv6_addr == NULL || rep_data == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    if (netmask_value == 128) {
        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV6_lock);
        SCRadixAddKeyIPV6((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
                  (void *)rep_data);
        SCMutexUnlock(&rep_ctx->reputationIPV6_lock);

    } else {
        if (netmask_value < 0 || netmask_value > 127) {
            SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "Invalid IPV6 Netblock");
            return NULL;
        }

        SCRadixChopIPAddressAgainstNetmask((uint8_t *)ipv6_addr, netmask_value, 128);

        /* Be careful with the mutex */
        SCMutexLock(&rep_ctx->reputationIPV6_lock);
        SCRadixAddKeyIPV6Netblock((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
                      (void *)rep_data, netmask_value);
        SCMutexUnlock(&rep_ctx->reputationIPV6_lock);
    }

    return rep_data;
}

/**
 * \brief Update a reputation or insert a new one. If it doesn't exist
 *        it will try to search for the reputation of parent subnets to
 *        create the new reputation data based on this one
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationUpdateIPV4Data(uint8_t *ipv4addr, ReputationTransaction *rtx)
{
    struct in_addr *ipv4_addr = (struct in_addr *) ipv4addr;
    Reputation *actual_rep;

    if (ipv4_addr == NULL || rtx == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV4_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    /* Be careful with the mutex */
    SCMutexLock(&rep_ctx->reputationIPV4_lock);

    /* Search exact match and update */
    actual_rep = SCReputationLookupIPV4ExactMatchReal(ipv4addr);
    if (actual_rep == NULL) {
        /* else search best match (parent subnets) */
        actual_rep =SCReputationLookupIPV4BestMatchReal(ipv4addr);

        if (actual_rep != NULL) {
            /* clone from parent and insert host */
            actual_rep = SCReputationClone(actual_rep);
        } else {
            /* else insert a new reputation data for the host */
            actual_rep = SCReputationAllocData();
            /* If new, we only increment values */
            rtx->flags = TRANSACTION_FLAG_INCS;
            rtx->flags |= TRANSACTION_FLAG_NEEDSYNC;
        }

        /* insert the reputation data in the tree */
        SCRadixAddKeyIPV4((uint8_t *)ipv4_addr, rep_ctx->reputationIPV4_tree,
              (void *)actual_rep);
    }
    /* Apply updates */
    SCReputationApplyTransaction(actual_rep, rtx);

    /* Unlock! */
    SCMutexUnlock(&rep_ctx->reputationIPV4_lock);

    return actual_rep;
}

/**
 * \brief Update a reputation or insert a new one. If it doesn't exist
 *        it will try to search for the reputation of parent subnets to
 *        create the new reputation data based on this one
 *
 * \param ipv6addr pointer to the ipv6 address key
 * \param rep_data Reputation pointer to the Reputation associated to the host/net
 *
 * \retval NULL On failure
 */
Reputation *SCReputationUpdateIPV6Data(uint8_t *ipv6addr, ReputationTransaction *rtx)
{
    struct in_addr *ipv6_addr = (struct in_addr *) ipv6addr;
    Reputation *actual_rep;

    if (ipv6_addr == NULL || rtx == NULL || rep_ctx == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid arguments");
        return NULL;
    }

    /* If the reputation tree is not initialized yet */
    if (rep_ctx->reputationIPV6_tree == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Reputation trees not initialized");
        return NULL;
    }

    /* Be careful with the mutex */
    SCMutexLock(&rep_ctx->reputationIPV6_lock);

    /* Search exact match and update */
    actual_rep = SCReputationLookupIPV6ExactMatchReal(ipv6addr);
    if (actual_rep == NULL) {
        /* else search best match (parent subnets) */
        actual_rep =SCReputationLookupIPV6BestMatchReal(ipv6addr);

        if (actual_rep != NULL) {
            /* clone from parent and insert host */
            actual_rep = SCReputationClone(actual_rep);
        } else {
            /* else insert a new reputation data for the host */
            actual_rep = SCReputationAllocData();
            /* If new, we only increment values */
            rtx->flags = TRANSACTION_FLAG_INCS;
            rtx->flags |= TRANSACTION_FLAG_NEEDSYNC;
        }

        /* insert the reputation data in the tree */
        SCRadixAddKeyIPV6((uint8_t *)ipv6_addr, rep_ctx->reputationIPV6_tree,
              (void *)actual_rep);
    }
    /* Apply updates */
    SCReputationApplyTransaction(actual_rep, rtx);

    /* Unlock! */
    SCMutexUnlock(&rep_ctx->reputationIPV6_lock);

    return actual_rep;
}


/* ----------------- UNITTESTS-------------------- */
#ifdef UNITTESTS

/**
 * \test Adding (from numeric ipv4) and removing host reputation in the Reputation context
 *       tree. THe reputation data is the real one, no copies here.
 */
int SCReputationTestIPV4AddRemoveHost01()
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 31, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || rep_data == rep_orig)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.8", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data != NULL)
        goto error;


    /* Removing */
    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    SCReputationRemoveIPV4Data((uint8_t *) &in, 32);

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
        goto error;

    SCReputationRemoveIPV4Data((uint8_t *) &in, 32);
    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv6) and removing host reputation in the Reputation context
 *       tree. THe reputation data is the real one, no copies here.
 */
int SCReputationTestIPV6AddRemoveHost01()
{
    uint8_t in[16];
    uint8_t i = 0;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
         goto error;

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 1;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 8;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);

    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 127, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || rep_data == rep_orig)
        goto error;


    /* Removing */
    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    SCReputationRemoveIPV6Data((uint8_t *) &in, 128);

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
        goto error;

    SCReputationRemoveIPV6Data((uint8_t *) &in, 128);
    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv4) and retrieving reputations
 *       tree. The reputation data retireved are copies of the original.
 */
int SCReputationTestIPV4AddRemoveHost02()
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.7", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 9;

    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 31, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV4ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Adding (from numeric ipv6) and removing host reputation in the Reputation context
 *       tree. The reputation data retireved are copies of the original.
 */
int SCReputationTestIPV6AddRemoveHost02()
{
    int i = 0;
    uint8_t in[16];

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2362", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    Reputation *rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;
    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 128, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 0)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2363", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 9;

    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 127, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_orig) == 1)
        goto error;

    if (inet_pton(AF_INET6, "aaaa:bbbb:cccc:dddd:1223:1722:3425:2364", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV6ExactMatch((uint8_t *) &in);
    /* It should return the host info and not the subnet info */
    if (rep_data != NULL)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Test searches (best and exact matches)
 */
int SCReputationTestIPV4BestExactMatch01()
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_origC = NULL;
    Reputation *rep_origB = NULL;
    Reputation *rep_origA = NULL;

    Reputation *rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.6", &in) < 0)
         goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 6;

    /* adding a host */
    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 32, rep_orig);
    if (rep_orig == NULL)
        goto error;
    Reputation *rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_orig)
        goto error;

    rep_orig = SCReputationAllocData();
    if (rep_orig == NULL)
        goto error;

    /* Adding C subnet */
    if (inet_pton(AF_INET, "192.168.1.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origC = SCReputationAddIPV4Data((uint8_t *) &in, 24, rep_orig);
    if (rep_origC == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    rep_orig = SCReputationAllocData();
    /* Adding B subnet */
    if (inet_pton(AF_INET, "192.168.0.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origB = SCReputationAddIPV4Data((uint8_t *) &in, 16, rep_orig);
    if (rep_origB == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    if (inet_pton(AF_INET, "192.168.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origB)
        goto error;

    rep_orig = SCReputationAllocData();
    /* Adding A subnet */
    if (inet_pton(AF_INET, "192.0.0.0", &in) < 0)
         goto error;

    for (i = 0; i < REPUTATION_NUMBER; i++)
        rep_orig->reps[i] = i * 10 + 7;

    rep_origA = SCReputationAddIPV4Data((uint8_t *) &in, 8, rep_orig);
    if (rep_origA == NULL)
        goto error;

    if (inet_pton(AF_INET, "192.168.1.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origC)
        goto error;

    if (inet_pton(AF_INET, "192.168.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origB)
        goto error;

    if (inet_pton(AF_INET, "192.167.2.5", &in) < 0)
         goto error;

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data != NULL)
        goto error;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || rep_data != rep_origA)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);

    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;
error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Update transactions
 */
int SCReputationTestIPV4Update01()
{
    int i = 0;
    struct in_addr in;

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();

    ReputationTransaction rtx;
    memset(&rtx, 0, sizeof(ReputationTransaction));
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_orig->reps[i] = 10;
    }

    if (inet_pton(AF_INET, "192.168.0.0", &in) < 0)
         goto error;

    /* Add add it as net */
    rep_orig = SCReputationAddIPV4Data((uint8_t *) &in, 16, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rtx.dec[REPUTATION_DDOS] = 5;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 30;
    rtx.flags |= TRANSACTION_FLAG_NEEDSYNC;
    rtx.flags |= TRANSACTION_FLAG_INCS;
    rtx.flags |= TRANSACTION_FLAG_DECS;

    if (inet_pton(AF_INET, "192.168.10.100", &in) < 0)
         goto error;

    /* Update (it will create the host entry with the data of the net) */
    SCReputationUpdateIPV4Data((uint8_t *)&in, &rtx);

    /* Create the reputation that any host 192.168.* should have */
    Reputation *rep_aux = SCReputationAllocData();

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_aux->reps[i] = 10;
    }

    rep_aux->reps[REPUTATION_DDOS] = 5;
    rep_aux->reps[REPUTATION_PHISH] = 60;
    rep_aux->reps[REPUTATION_MALWARE] = 40;

    Reputation *rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* Now that is created, it should update only the host */
    rtx.dec[REPUTATION_DDOS] = 50;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 50;

    rep_aux->reps[REPUTATION_DDOS] = 0;
    rep_aux->reps[REPUTATION_PHISH] = 110;
    rep_aux->reps[REPUTATION_MALWARE] = 90;

    SCReputationUpdateIPV4Data((uint8_t *)&in, &rtx);

    rep_data = SCReputationLookupIPV4ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* So let's see if we add a host and get the parent data again */
    if (inet_pton(AF_INET, "192.168.10.101", &in) < 0)
         goto error;

    rep_aux->reps[REPUTATION_DDOS] = 10;
    rep_aux->reps[REPUTATION_PHISH] = 10;
    rep_aux->reps[REPUTATION_MALWARE] = 10;

    rep_data = SCReputationLookupIPV4BestMatchReal((uint8_t *) &in);

    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV4_tree);
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

/**
 * \test Update transactions
 */
int SCReputationTestIPV6Update01()
{
    int i = 0;
    uint8_t in[16];

    SCReputationInitCtx();
    if (rep_ctx == NULL) {
        SCLogInfo("Error initializing Reputation Module");
        return 0;
    }

    Reputation *rep_orig = SCReputationAllocData();

    ReputationTransaction rtx;
    memset(&rtx, 0, sizeof(ReputationTransaction));
    if (rep_orig == NULL)
        goto error;

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_orig->reps[i] = 10;
    }

    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1DDD", &in) < 0)
         goto error;

    /* Add add it as net */
    rep_orig = SCReputationAddIPV6Data((uint8_t *) &in, 98, rep_orig);
    if (rep_orig == NULL)
        goto error;

    rtx.dec[REPUTATION_DDOS] = 5;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 30;
    rtx.flags |= TRANSACTION_FLAG_NEEDSYNC;
    rtx.flags |= TRANSACTION_FLAG_INCS;
    rtx.flags |= TRANSACTION_FLAG_DECS;

    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1ABA", &in) < 0)
         goto error;

    /* Update (it will create the host entry with the data of the net) */
    SCReputationUpdateIPV6Data((uint8_t *)&in, &rtx);

    /* Create the reputation that any host 192.168.* should have */
    Reputation *rep_aux = SCReputationAllocData();

    /* Fill the reputation with some values.. */
    for (i = 0; i < REPUTATION_NUMBER; i++) {
        rep_aux->reps[i] = 10;
    }

    rep_aux->reps[REPUTATION_DDOS] = 5;
    rep_aux->reps[REPUTATION_PHISH] = 60;
    rep_aux->reps[REPUTATION_MALWARE] = 40;

    Reputation *rep_data = SCReputationLookupIPV6BestMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* Now that is created, it should update only the host */
    rtx.dec[REPUTATION_DDOS] = 50;
    rtx.inc[REPUTATION_PHISH] = 50;
    rtx.inc[REPUTATION_MALWARE] = 50;

    rep_aux->reps[REPUTATION_DDOS] = 0;
    rep_aux->reps[REPUTATION_PHISH] = 110;
    rep_aux->reps[REPUTATION_MALWARE] = 90;

    SCReputationUpdateIPV6Data((uint8_t *)&in, &rtx);

    rep_data = SCReputationLookupIPV6ExactMatchReal((uint8_t *) &in);
    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    /* So let's see if we add a host and get the parent data again */
    if (inet_pton(AF_INET6, "8762:2352:6261:7265:EE23:21AD:2121:1ACB", &in) < 0)
         goto error;

    rep_aux->reps[REPUTATION_DDOS] = 10;
    rep_aux->reps[REPUTATION_PHISH] = 10;
    rep_aux->reps[REPUTATION_MALWARE] = 10;

    rep_data = SCReputationLookupIPV6BestMatchReal((uint8_t *) &in);


    if (rep_data == NULL || SCReputationEqual(rep_data, rep_aux) != 1)
        goto error;

    SCRadixPrintTree(rep_ctx->reputationIPV6_tree);
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 1;

error:
    SCReputationFreeCtx(rep_ctx);
    rep_ctx = NULL;
    return 0;
}

#endif /* UNITTESTS */

/** Register the following unittests for the Reputation module */
void SCReputationRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCReputationTestIPV4AddRemoveHost01",
                   SCReputationTestIPV4AddRemoveHost01, 1);
    UtRegisterTest("SCReputationTestIPV6AddRemoveHost01",
                   SCReputationTestIPV6AddRemoveHost01, 1);

    UtRegisterTest("SCReputationTestIPV4BestExactMatch01",
                   SCReputationTestIPV4BestExactMatch01, 1);

    UtRegisterTest("SCReputationTestIPV4AddRemoveHost02",
                   SCReputationTestIPV4AddRemoveHost02, 1);
    UtRegisterTest("SCReputationTestIPV6AddRemoveHost02",
                   SCReputationTestIPV6AddRemoveHost02, 1);

    UtRegisterTest("SCReputationTestIPV4Update01",
                   SCReputationTestIPV4Update01, 1);
    UtRegisterTest("SCReputationTestIPV6Update01",
                   SCReputationTestIPV6Update01, 1);
#endif /* UNITTESTS */
}

