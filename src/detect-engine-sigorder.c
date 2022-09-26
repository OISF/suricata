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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Signature ordering part of the detection engine.
 */

#include "suricata-common.h"
#include "detect-xbits.h"
#include "detect-flowbits.h"
#include "detect-flowint.h"
#include "detect-engine-sigorder.h"
#include "detect-pcre.h"
#include "detect-engine-build.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-action.h"
#include "flow-util.h"

#ifdef DEBUG
#include "action-globals.h"
#include "util-debug.h"
#include "detect-parse.h"
#include "detect.h"
#endif
#define DETECT_FLOWVAR_NOT_USED      1
#define DETECT_FLOWVAR_TYPE_READ     2
#define DETECT_FLOWVAR_TYPE_SET_READ 3
#define DETECT_FLOWVAR_TYPE_SET      4

#define DETECT_PKTVAR_NOT_USED      1
#define DETECT_PKTVAR_TYPE_READ     2
#define DETECT_PKTVAR_TYPE_SET_READ 3
#define DETECT_PKTVAR_TYPE_SET      4

#define DETECT_FLOWBITS_NOT_USED      1
#define DETECT_FLOWBITS_TYPE_READ     2
#define DETECT_FLOWBITS_TYPE_SET_READ 3
#define DETECT_FLOWBITS_TYPE_SET      4

#define DETECT_FLOWINT_NOT_USED      1
#define DETECT_FLOWINT_TYPE_READ     2
#define DETECT_FLOWINT_TYPE_SET_READ 3
#define DETECT_FLOWINT_TYPE_SET      4

#define DETECT_XBITS_NOT_USED      1
#define DETECT_XBITS_TYPE_READ     2
#define DETECT_XBITS_TYPE_SET_READ 3
#define DETECT_XBITS_TYPE_SET      4


/**
 * \brief Registers a keyword-based, signature ordering function
 *
 * \param de_ctx  Pointer to the detection engine context from which the
 *                signatures have to be ordered.
 * \param FuncPtr Pointer to the signature ordering function.  The prototype of
 *                the signature ordering function should accept a pointer to a
 *                SCSigSignatureWrapper as its argument and shouldn't return
 *                anything
 */
static void SCSigRegisterSignatureOrderingFunc(DetectEngineCtx *de_ctx,
                                               int (*SWCompare)(SCSigSignatureWrapper *sw1, SCSigSignatureWrapper *sw2))
{
    SCSigOrderFunc *curr = NULL;
    SCSigOrderFunc *prev = NULL;
    SCSigOrderFunc *temp = NULL;

    curr = de_ctx->sc_sig_order_funcs;

    /* Walk to the end of the list, and leave prev pointing at the
       last element. */
    prev = curr;
    while (curr != NULL) {
        if (curr->SWCompare == SWCompare) {
            /* Already specified this compare */
            return;
        }
        prev = curr;
        curr = curr->next;
    }

    if ( (temp = SCMalloc(sizeof(SCSigOrderFunc))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in SCSigRegisterSignatureOrderingFunc. Exiting...");
    }
    memset(temp, 0, sizeof(SCSigOrderFunc));

    temp->SWCompare = SWCompare;

    /* Append the new compare function at the end of the list. */
    if (prev == NULL)
        de_ctx->sc_sig_order_funcs = temp;
    else
        prev->next = temp;

    return;
}

/**
 * \brief Returns the flowbit type set for this signature.  If more than one
 *        flowbit has been set for the same rule, we return the flowbit type of
 *        the maximum priority/value, where priority/value is maximum for the
 *        ones that set the value and the lowest for ones that read the value.
 *        If no flowbit has been set for the rule, we return 0, which indicates
 *        the least value amongst flowbit types.
 *
 * \param sig Pointer to the Signature from which the flowbit value has to be
 *            returned.
 *
 * \retval flowbits The flowbits type for this signature if it is set; if it is
 *                  not set, return 0
 */
static inline int SCSigGetFlowbitsType(Signature *sig)
{
    DetectFlowbitsData *fb = NULL;
    int flowbits_user_type = DETECT_FLOWBITS_NOT_USED;
    int read = 0;
    int write = 0;
    SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];

    while (sm != NULL) {
        if (sm->type == DETECT_FLOWBITS) {
            fb = (DetectFlowbitsData *)sm->ctx;
            if (fb->cmd == DETECT_FLOWBITS_CMD_ISNOTSET ||
                fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                read++;
            } else {
#ifdef DEBUG
                BUG_ON(1);
#endif
            }
        }

        sm = sm->next;
    }

    sm = sig->init_data->smlists[DETECT_SM_LIST_POSTMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_FLOWBITS) {
            fb = (DetectFlowbitsData *)sm->ctx;
            if (fb->cmd == DETECT_FLOWBITS_CMD_SET ||
                fb->cmd == DETECT_FLOWBITS_CMD_UNSET ||
                fb->cmd == DETECT_FLOWBITS_CMD_TOGGLE) {
                write++;
            } else {
#ifdef DEBUG
                BUG_ON(1);
#endif
            }
        }

        sm = sm->next;
    }

    if (read > 0 && write == 0) {
        flowbits_user_type = DETECT_FLOWBITS_TYPE_READ;
    } else if (read == 0 && write > 0) {
        flowbits_user_type = DETECT_FLOWBITS_TYPE_SET;
    } else if (read > 0 && write > 0) {
        flowbits_user_type = DETECT_FLOWBITS_TYPE_SET_READ;
    }

    SCLogDebug("Sig %s typeval %d", sig->msg, flowbits_user_type);

    return flowbits_user_type;
}

static inline int SCSigGetFlowintType(Signature *sig)
{
    DetectFlowintData *fi = NULL;
    int flowint_user_type = DETECT_FLOWINT_NOT_USED;
    int read = 0;
    int write = 0;
    SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];

    while (sm != NULL) {
        if (sm->type == DETECT_FLOWINT) {
            fi = (DetectFlowintData *)sm->ctx;
            if (fi->modifier == FLOWINT_MODIFIER_LT ||
                fi->modifier == FLOWINT_MODIFIER_LE ||
                fi->modifier == FLOWINT_MODIFIER_EQ ||
                fi->modifier == FLOWINT_MODIFIER_NE ||
                fi->modifier == FLOWINT_MODIFIER_GE ||
                fi->modifier == FLOWINT_MODIFIER_GT ||
                fi->modifier == FLOWINT_MODIFIER_NOTSET ||
                fi->modifier == FLOWINT_MODIFIER_ISSET) {
                read++;
            } else {
#ifdef DEBUG
                BUG_ON(1);
#endif
            }
        }

        sm = sm->next;
    }

    sm = sig->init_data->smlists[DETECT_SM_LIST_POSTMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_FLOWINT) {
            fi = (DetectFlowintData *)sm->ctx;
            if (fi->modifier == FLOWINT_MODIFIER_SET ||
                fi->modifier == FLOWINT_MODIFIER_ADD ||
                fi->modifier == FLOWINT_MODIFIER_SUB) {
                write++;
            } else {
#ifdef DEBUG
                BUG_ON(1);
#endif
            }
        }

        sm = sm->next;
    }

    if (read > 0 && write == 0) {
        flowint_user_type = DETECT_FLOWINT_TYPE_READ;
    } else if (read == 0 && write > 0) {
        flowint_user_type = DETECT_FLOWINT_TYPE_SET;
    } else if (read > 0 && write > 0) {
        flowint_user_type = DETECT_FLOWINT_TYPE_SET_READ;
    }

    SCLogDebug("Sig %s typeval %d", sig->msg, flowint_user_type);

    return flowint_user_type;
}

/**
 * \brief Returns whether the flowvar set for this rule, sets the flowvar or
 *        reads the flowvar.  If the rule sets the flowvar the function returns
 *        DETECT_FLOWVAR_TYPE_SET(3), if it reads the flowvar the function
 *        returns DETECT_FLOWVAR_TYPE_READ(2), and if flowvar is not used in this
 *        rule the function returns DETECT_FLOWVAR_NOT_USED(1)
 *
 * \param sig Pointer to the Signature from which the flowvar type has to be
 *            returned.
 *
 * \retval type DETECT_FLOWVAR_TYPE_SET(3) if the rule sets the flowvar,
 *              DETECT_FLOWVAR_TYPE_READ(2) if it reads, and
 *              DETECT_FLOWVAR_NOT_USED(1) if flowvar is not used.
 */
static inline int SCSigGetFlowvarType(Signature *sig)
{
    DetectPcreData *pd = NULL;
    int type = DETECT_FLOWVAR_NOT_USED;
    int read = 0;
    int write = 0;
    SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_PMATCH];

    while (sm != NULL) {
        pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_PCRE) {
            uint8_t x;
            for (x = 0; x < pd->idx; x++) {
                if (pd->captypes[x] == VAR_TYPE_FLOW_VAR) {
                    write++;
                    break;
                }
            }
        }

        sm = sm->next;
    }

    sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];
    pd = NULL;
    while (sm != NULL) {
        if (sm->type == DETECT_FLOWVAR) {
            read++;
        }

        sm = sm->next;
    }

    if (read > 0 && write == 0) {
        type = DETECT_FLOWVAR_TYPE_READ;
    } else if (read == 0 && write > 0) {
        type = DETECT_FLOWVAR_TYPE_SET;
    } else if (read > 0 && write > 0) {
        type = DETECT_FLOWVAR_TYPE_SET_READ;
    }

    return type;
}

/**
 * \brief Returns whether the pktvar set for this rule, sets the flowvar or
 *        reads the pktvar.  If the rule sets the pktvar the function returns
 *        DETECT_PKTVAR_TYPE_SET(3), if it reads the pktvar the function
 *        returns DETECT_PKTVAR_TYPE_READ(2), and if pktvar is not used in this
 *        rule the function returns DETECT_PKTVAR_NOT_USED(1)
 *
 * \param sig Pointer to the Signature from which the pktvar type has to be
 *            returned.
 *
 * \retval type DETECT_PKTVAR_TYPE_SET(3) if the rule sets the flowvar,
 *              DETECT_PKTVAR_TYPE_READ(2) if it reads, and
 *              DETECT_PKTVAR_NOT_USED(1) if pktvar is not used.
 */
static inline int SCSigGetPktvarType(Signature *sig)
{
    DetectPcreData *pd = NULL;
    int type = DETECT_PKTVAR_NOT_USED;
    int read = 0;
    int write = 0;
    SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_PMATCH];

    while (sm != NULL) {
        pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_PCRE) {
            uint8_t x;
            for (x = 0; x < pd->idx; x++) {
                if (pd->captypes[x] == VAR_TYPE_PKT_VAR) {
                    write++;
                    break;
                }
            }
        }

        sm = sm->next;
    }

    sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];
    pd = NULL;
    while (sm != NULL) {
        if (sm->type == DETECT_PKTVAR) {
            read++;
        }

        sm = sm->next;
    }

    if (read > 0 && write == 0) {
        type = DETECT_PKTVAR_TYPE_READ;
    } else if (read == 0 && write > 0) {
        type = DETECT_PKTVAR_TYPE_SET;
    } else if (read > 0 && write > 0) {
        type = DETECT_PKTVAR_TYPE_SET_READ;
    }

    return type;
}

/**
 * \brief Returns the xbit type set for this signature.  If more than one
 *        xbit has been set for the same rule, we return the xbit type of
 *        the maximum priority/value, where priority/value is maximum for the
 *        ones that set the value and the lowest for ones that read the value.
 *        If no xbit has been set for the rule, we return 0, which indicates
 *        the least value amongst xbit types.
 *
 * \param sig Pointer to the Signature from which the xbit value has to be
 *            returned.
 *
 * \retval xbits The xbits type for this signature if it is set; if it is
 *                  not set, return 0
 */
static inline int SCSigGetXbitsType(Signature *sig, enum VarTypes type)
{
    DetectXbitsData *fb = NULL;
    int xbits_user_type = DETECT_XBITS_NOT_USED;
    int read = 0;
    int write = 0;
    SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];

    while (sm != NULL) {
        if (sm->type == DETECT_XBITS) {
            fb = (DetectXbitsData *)sm->ctx;
            if (fb->type == type) {
                if (fb->cmd == DETECT_XBITS_CMD_ISNOTSET ||
                        fb->cmd == DETECT_XBITS_CMD_ISSET) {
                    read++;
                } else {
#ifdef DEBUG
                    BUG_ON(1);
#endif
                }
            }
        }

        sm = sm->next;
    }

    sm = sig->init_data->smlists[DETECT_SM_LIST_POSTMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_HOSTBITS) {
            fb = (DetectXbitsData *)sm->ctx;
            if (fb->type == type) {
                if (fb->cmd == DETECT_XBITS_CMD_SET ||
                        fb->cmd == DETECT_XBITS_CMD_UNSET ||
                        fb->cmd == DETECT_XBITS_CMD_TOGGLE) {
                    write++;
                } else {
#ifdef DEBUG
                    BUG_ON(1);
#endif
                }
            }
        }

        sm = sm->next;
    }

    if (read > 0 && write == 0) {
        xbits_user_type = DETECT_XBITS_TYPE_READ;
    } else if (read == 0 && write > 0) {
        xbits_user_type = DETECT_XBITS_TYPE_SET;
    } else if (read > 0 && write > 0) {
        xbits_user_type = DETECT_XBITS_TYPE_SET_READ;
    }

    SCLogDebug("Sig %s typeval %d", sig->msg, xbits_user_type);

    return xbits_user_type;
}

/**
 * \brief Processes the flowbits data for this signature and caches it for
 *        future use.  This is needed to optimize the sig_ordering module.
 *
 * \param sw The sigwrapper/signature for which the flowbits data has to be
 *           cached
 */
static inline void SCSigProcessUserDataForFlowbits(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_FLOWBITS] = SCSigGetFlowbitsType(sw->sig);
}

/**
 * \brief Processes the flowvar data for this signature and caches it for
 *        future use.  This is needed to optimize the sig_ordering module.
 *
 * \param sw The sigwrapper/signature for which the flowvar data has to be
 *           cached
 */
static inline void SCSigProcessUserDataForFlowvar(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_FLOWVAR] = SCSigGetFlowvarType(sw->sig);
}

static inline void SCSigProcessUserDataForFlowint(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_FLOWINT] = SCSigGetFlowintType(sw->sig);
}

/**
 * \brief Processes the pktvar data for this signature and caches it for
 *        future use.  This is needed to optimize the sig_ordering module.
 *
 * \param sw The sigwrapper/signature for which the pktvar data has to be
 *           cached
 */
static inline void SCSigProcessUserDataForPktvar(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_PKTVAR] = SCSigGetPktvarType(sw->sig);
}

/**
 * \brief Processes the hostbits data for this signature and caches it for
 *        future use.  This is needed to optimize the sig_ordering module.
 *
 * \param sw The sigwrapper/signature for which the hostbits data has to be
 *           cached
 */
static inline void SCSigProcessUserDataForHostbits(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_HOSTBITS] = SCSigGetXbitsType(sw->sig, VAR_TYPE_HOST_BIT);
}

/**
 * \brief Processes the hostbits data for this signature and caches it for
 *        future use.  This is needed to optimize the sig_ordering module.
 *
 * \param sw The sigwrapper/signature for which the hostbits data has to be
 *           cached
 */
static inline void SCSigProcessUserDataForIPPairbits(SCSigSignatureWrapper *sw)
{
    sw->user[SC_RADIX_USER_DATA_IPPAIRBITS] = SCSigGetXbitsType(sw->sig, VAR_TYPE_IPPAIR_BIT);
}

/* Return 1 if sw1 comes before sw2 in the final list. */
static int SCSigLessThan(SCSigSignatureWrapper *sw1,
                         SCSigSignatureWrapper *sw2,
                         SCSigOrderFunc *cmp_func_list)
{
    SCSigOrderFunc *funcs = cmp_func_list;

    while (funcs != NULL) {
        int delta = funcs->SWCompare(sw1, sw2);
        if (delta > 0)
            return 1;
        else if (delta < 0)
            return 0;

        funcs = funcs->next;
    }
    // They are equal, so use sid as the final decider.
    return sw1->sig->id < sw2->sig->id;
}

/* Merge sort based on a list of compare functions */
static SCSigSignatureWrapper *SCSigOrder(SCSigSignatureWrapper *sw,
                                         SCSigOrderFunc *cmp_func_list)
{
    SCSigSignatureWrapper *subA = NULL;
    SCSigSignatureWrapper *subB = NULL;
    SCSigSignatureWrapper *first;
    SCSigSignatureWrapper *second;
    SCSigSignatureWrapper *result = NULL;
    SCSigSignatureWrapper *last = NULL;
    SCSigSignatureWrapper *new = NULL;

    /* Divide input list into two sub-lists. */
    while (sw != NULL) {
        first = sw;
        sw = sw->next;
        /* Push the first element onto sub-list A */
        first->next = subA;
        subA = first;

        if (sw == NULL)
            break;
        second = sw;
        sw = sw->next;
        /* Push the second element onto sub-list B */
        second->next = subB;
        subB = second;
    }
    if (subB == NULL) {
        /* Only zero or one element on the list. */
        return subA;
    }

    /* Now sort each list */
    subA = SCSigOrder(subA, cmp_func_list);
    subB = SCSigOrder(subB, cmp_func_list);

    /* Merge the two sorted lists. */
    while (subA != NULL && subB != NULL) {
        if (SCSigLessThan(subA, subB, cmp_func_list)) {
            new = subA;
            subA = subA->next;
        } else {
          new = subB;
          subB = subB->next;
        }
        /* Push onto the end of the output list. */
        new->next = NULL;
        if (result == NULL) {
            result = new;
            last = new;
        } else {
            last->next = new;
            last = new;
        }
    }
    /* Attach the rest of any remaining list. Only one can be non-NULL here. */
    if (subA == NULL)
        last->next = subB;
    else if (subB == NULL)
        last->next = subA;

    return result;
}

/**
 * \brief Orders an incoming Signature based on its action
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its action
 */
static int SCSigOrderByActionCompare(SCSigSignatureWrapper *sw1,
                                     SCSigSignatureWrapper *sw2)
{
    return ActionOrderVal(sw2->sig->action) - ActionOrderVal(sw1->sig->action);
}

/**
 * \brief Orders an incoming Signature based on its flowbits type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its flowbits
 */
static int SCSigOrderByFlowbitsCompare(SCSigSignatureWrapper *sw1,
                                       SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_FLOWBITS] -
        sw2->user[SC_RADIX_USER_DATA_FLOWBITS];
}

/**
 * \brief Orders an incoming Signature based on its flowvar type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its flowvar
 */
static int SCSigOrderByFlowvarCompare(SCSigSignatureWrapper *sw1,
                                      SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_FLOWVAR] -
        sw2->user[SC_RADIX_USER_DATA_FLOWVAR];
}

/**
 * \brief Orders an incoming Signature based on its pktvar type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its pktvar
 */
static int SCSigOrderByPktvarCompare(SCSigSignatureWrapper *sw1,
                                     SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_PKTVAR] -
        sw2->user[SC_RADIX_USER_DATA_PKTVAR];
}

static int SCSigOrderByFlowintCompare(SCSigSignatureWrapper *sw1,
                                      SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_FLOWINT] -
        sw2->user[SC_RADIX_USER_DATA_FLOWINT];
}

/**
 * \brief Orders an incoming Signature based on its hostbits type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its hostbits
 */
static int SCSigOrderByHostbitsCompare(SCSigSignatureWrapper *sw1,
                                       SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_HOSTBITS] -
        sw2->user[SC_RADIX_USER_DATA_HOSTBITS];
}

/**
 * \brief Orders an incoming Signature based on its ippairbits (xbits) type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its bits
 */
static int SCSigOrderByIPPairbitsCompare(SCSigSignatureWrapper *sw1,
                                         SCSigSignatureWrapper *sw2)
{
    return sw1->user[SC_RADIX_USER_DATA_IPPAIRBITS] -
        sw2->user[SC_RADIX_USER_DATA_IPPAIRBITS];
}

/**
 * \brief Orders an incoming Signature based on its priority type
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 * \param sw     The new signature that has to be ordered based on its priority
 */
static int SCSigOrderByPriorityCompare(SCSigSignatureWrapper *sw1,
                                       SCSigSignatureWrapper *sw2)
{
    if (sw1->sig->prio > sw2->sig->prio) {
        return -1;
    } else if (sw1->sig->prio < sw2->sig->prio) {
        return 1;
    }
    return 0;
}

/**
 * \brief Creates a Wrapper around the Signature
 *
 * \param Pointer to the Signature to be wrapped
 *
 * \retval sw Pointer to the wrapper that holds the signature
 */
static inline SCSigSignatureWrapper *SCSigAllocSignatureWrapper(Signature *sig)
{
    SCSigSignatureWrapper *sw = NULL;

    if ( (sw = SCMalloc(sizeof(SCSigSignatureWrapper))) == NULL)
        return NULL;
    memset(sw, 0, sizeof(SCSigSignatureWrapper));

    sw->sig = sig;

    /* Process data from the signature into a cache for further use by the
     * sig_ordering module */
    SCSigProcessUserDataForFlowbits(sw);
    SCSigProcessUserDataForFlowvar(sw);
    SCSigProcessUserDataForFlowint(sw);
    SCSigProcessUserDataForPktvar(sw);
    SCSigProcessUserDataForHostbits(sw);
    SCSigProcessUserDataForIPPairbits(sw);

    return sw;
}

/**
 * \brief Orders the signatures
 *
 * \param de_ctx Pointer to the Detection Engine Context that holds the
 *               signatures to be ordered
 */
void SCSigOrderSignatures(DetectEngineCtx *de_ctx)
{
    Signature *sig = NULL;
    SCSigSignatureWrapper *sigw = NULL;
    SCSigSignatureWrapper *sigw_list = NULL;

    int i = 0;
    SCLogDebug("ordering signatures in memory");

    sig = de_ctx->sig_list;
    while (sig != NULL) {
        sigw = SCSigAllocSignatureWrapper(sig);
        /* Push signature wrapper onto a list, order doesn't matter here. */
        sigw->next = sigw_list;
        sigw_list = sigw;

        sig = sig->next;
        i++;
    }

    /* Sort the list */
    sigw_list = SCSigOrder(sigw_list, de_ctx->sc_sig_order_funcs);

    SCLogDebug("Total Signatures to be processed by the"
           "sigordering module: %d", i);

    /* Recreate the sig list in order */
    de_ctx->sig_list = NULL;
    sigw = sigw_list;
    i = 0;
    while (sigw != NULL) {
        i++;
        sigw->sig->next = NULL;
        if (de_ctx->sig_list == NULL) {
            /* First entry on the list */
            de_ctx->sig_list = sigw->sig;
            sig = de_ctx->sig_list;
        } else {
            sig->next = sigw->sig;
            sig = sig->next;
        }
        SCSigSignatureWrapper *sigw_to_free = sigw;
        sigw = sigw->next;
        SCFree(sigw_to_free);
    }

    SCLogDebug("total signatures reordered by the sigordering module: %d", i);
}

/**
 * \brief Lets you register the Signature ordering functions.  The order in
 *        which the functions are registered shows the priority.  The first
 *        function registered provides more priority than the function
 *        registered after it.  To add a new registration function, register
 *        it by listing it in the correct position in the below sequence,
 *        based on the priority you would want to offer to that keyword.
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures have to be ordered.
 */
void SCSigRegisterSignatureOrderingFuncs(DetectEngineCtx *de_ctx)
{
    SCLogDebug("registering signature ordering functions");

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowintCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByHostbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByIPPairbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
}

/**
 * \brief De-registers all the signature ordering functions registered
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures were ordered.
 */
void SCSigSignatureOrderingModuleCleanup(DetectEngineCtx *de_ctx)
{
    SCSigOrderFunc *funcs;
    void *temp;

    /* clean the memory alloted to the signature ordering funcs */
    funcs = de_ctx->sc_sig_order_funcs;
    while (funcs != NULL) {
        temp = funcs;
        funcs = funcs->next;
        SCFree(temp);
    }
    de_ctx->sc_sig_order_funcs = NULL;
}

/**********Unittests**********/

DetectEngineCtx *DetectEngineCtxInit(void);
Signature *SigInit(DetectEngineCtx *, const char *);
void SigFree(DetectEngineCtx *, Signature *);
void DetectEngineCtxFree(DetectEngineCtx *);

#ifdef UNITTESTS

static int SCSigOrderingTest01(void)
{
    SCSigOrderFunc *temp = NULL;
    int i = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);

    temp = de_ctx->sc_sig_order_funcs;
    while (temp != NULL) {
        i++;
        temp = temp->next;
    }

    DetectEngineCtxFree(de_ctx);

    return (i == 5);
 end:
    return 0;
}

static int SCSigOrderingTest02(void)
{
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:2;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:3;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; flowvar:http_host,\"www.oisf.net\"; rev:4; priority:1; sid:4;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:1; sid:5;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; content:\"220\"; offset:10; depth:4; rev:4; priority:3; sid:6;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:7;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:8;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; rev:4; priority:3; flowbits:set,TEST.one; flowbits:noalert; sid:9;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:10;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:11;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:12;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; pktvar:http_host,\"www.oisf.net\"; priority:2; flowbits:isnotset,TEST.two; sid:13;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; flowbits:set,TEST.two; sid:14;)");
    FAIL_IF_NULL(sig);

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    /* pass */
    FAIL_IF_NOT(sig->id == 6);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 4);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 8);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 7);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 10);
    sig = sig->next;

    /* drops */
    FAIL_IF_NOT(sig->id == 9);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 13);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 2);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 3);
    sig = sig->next;

    /* alerts */
    FAIL_IF_NOT(sig->id == 14);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 5);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 1);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 11);
    sig = sig->next;
    FAIL_IF_NOT(sig->id == 12);
    sig = sig->next;

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int SCSigOrderingTest03(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; flowbits:unset,TEST.one; rev:4; priority:2; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; flowbits:isset,TEST.one; rev:4; priority:1; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; priority:2; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; flowbits:isnotset,TEST.one; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; rev:4; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; flowbits:unset,TEST.one; rev:4; priority:3; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; flowbits:toggle,TEST.one; rev:4; priority:1; pktvar:http_host,\"www.oisf.net\"; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;


    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; rev:4; flowbits:set,TEST.one; flowbits:noalert; pktvar:http_host,\"www.oisf.net\"; sid:9;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:10;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:11;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:12;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; flowbits:isnotset,TEST.one; sid:13;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; flowbits:set,TEST.one; sid:14;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 9);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 14);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 13);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 10);
    sig = sig->next;
    result &= (sig->id == 11);
    sig = sig->next;
    result &= (sig->id == 12);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest04(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; content:\"220\"; offset:10; rev:4; priority:3; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; rev:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; rev:4; priority:3; flowvar:http_host,\"www.oisf.net\"; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; pktvar:http_host,\"www.oisf.net\"; rev:4; priority:1; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; flowvar:http_host,\"www.oisf.net\"; pktvar:http_host,\"www.oisf.net\"; priority:1; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; flowvar:http_host,\"www.oisf.net\"; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; flowvar:http_host,\"www.oisf.net\"; sid:9;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    /* flowvar set */
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 9);
    sig = sig->next;

    /* pktvar */
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;

    result &= (sig->id == 1);
    sig = sig->next;

end:
    if (de_ctx)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest05(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; content:\"220\"; offset:10; rev:4; priority:3; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; rev:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; rev:4; priority:3; pktvar:http_host,\"www.oisf.net\"; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; pktvar:http_host,\"www.oisf.net\"; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;
    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; pktvar:http_host,\"www.oisf.net\"; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;


    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

    //#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
    //#endif

    sig = de_ctx->sig_list;

    /* pktvar set */
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    /* pktvar read */
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;

    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest06(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; rev:4; priority:2; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; rev:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; rev:4; priority:2; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:1; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);


    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;


end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest07(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:1; rev:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; sid:2; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:10; depth:4; sid:3; rev:4; priority:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; depth:4; sid:4; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:5; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering drop\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:6; rev:4; priority:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering reject\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:7; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; sid:8; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Order with a different Action priority
 * (as specified from config)
 */
static int SCSigOrderingTest08(void)
{
#ifdef HAVE_LIBNET11
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;
    extern uint8_t action_order_sigs[4];

    /* Let's change the order. Default is pass, drop, reject, alert (pass has highest prio) */
    action_order_sigs[0] = ACTION_REJECT;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_ALERT;
    action_order_sigs[3] = ACTION_PASS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:1; rev:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; sid:2; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:10; depth:4; sid:3; rev:4; priority:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; depth:4; sid:4; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:5; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "reject tcp any !21:902 -> any any (msg:\"Testing sigordering drop\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:6; rev:4; priority:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering reject\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; sid:7; rev:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; sid:8; rev:4; priority:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;

end:
    /* Restore the default pre-order definition */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
#else
    return 1;
#endif
}

/**
 * \test Order with a different Action priority
 * (as specified from config)
 */
static int SCSigOrderingTest09(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;
    extern uint8_t action_order_sigs[4];

    /* Let's change the order. Default is pass, drop, reject, alert (pass has highest prio) */
    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_REJECT;
    action_order_sigs[2] = ACTION_ALERT;
    action_order_sigs[3] = ACTION_PASS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; priority:2; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:10; depth:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; depth:4; rev:4; priority:2; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering drop\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:1; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering reject\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;

end:
    /* Restore the default pre-order definition */
    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_REJECT;
    action_order_sigs[2] = ACTION_PASS;
    action_order_sigs[3] = ACTION_ALERT;
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Order with a different Action priority
 * (as specified from config)
 */
static int SCSigOrderingTest10(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;
    extern uint8_t action_order_sigs[4];

    /* Let's change the order. Default is pass, drop, reject, alert (pass has highest prio) */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_ALERT;
    action_order_sigs[2] = ACTION_DROP;
    action_order_sigs[3] = ACTION_REJECT;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; rev:4; priority:2; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:10; depth:4; rev:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:10; depth:4; rev:4; priority:2; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering pass\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering drop\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:1; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering reject\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering alert\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;

end:
    /* Restore the default pre-order definition */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest11(void)
{
    int result = 0;
    Signature *prevsig = NULL, *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering set\"; flowbits:isnotset,myflow1; rev:4; sid:1;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig = sig;
    de_ctx->sig_list = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering toggle\"; flowbits:toggle,myflow2; rev:4; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering unset\"; flowbits:isset, myflow1; flowbits:unset,myflow2; rev:4; priority:3; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByActionCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPktvarCompare);
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

    sig = de_ctx->sig_list;

#ifdef DEBUG
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigOrderingTest12(void)
{
    Signature *sig = NULL;
    Packet *p = NULL;
    uint8_t buf[] = "test message";
    int result = 0;
    Flow f;

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_UNKNOWN;
    f.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    const char *sigs[2];
    sigs[0] = "alert tcp any any -> any any (content:\"test\"; dsize:>0; flowbits:isset,one; flowbits:set,two; sid:1;)";
    sigs[1] = "alert tcp any any -> any any (content:\"test\"; dsize:>0; flowbits:set,one; sid:2;)";
    UTHAppendSigs(de_ctx, sigs, 2);

    sig = de_ctx->sig_list;
    if (sig == NULL)
        goto end;
    if (sig->next == NULL)
        goto end;
    if (sig->next->next != NULL)
        goto end;
    if (de_ctx->signum != 2)
        goto end;

    FlowInitConfig(FLOW_QUIET);
    p = UTHBuildPacket(buf, sizeof(buf), IPPROTO_TCP);
    if (p == NULL) {
        printf("Error building packet.");
        goto end;
    }
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    UTHMatchPackets(de_ctx, &p, 1);

    uint32_t sids[2] = {1, 2};
    uint32_t results[2] = {1, 1};
    result = UTHCheckPacketMatchResults(p, sids, results, 2);

end:
    if (p != NULL)
        SCFree(p);
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    FlowShutdown();

    return result;
}

/** \test Bug 1061 */
static int SCSigOrderingTest13(void)
{
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flowbits:isset,bit1; flowbits:set,bit2; flowbits:set,bit3; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flowbits:set,bit1; flowbits:set,bit2; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flowbits:isset,bit1; flowbits:isset,bit2; flowbits:isset,bit3; sid:5;)");
    if (sig == NULL) {
        goto end;
    }

    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByFlowbitsCompare);
    SCSigOrderSignatures(de_ctx);

    result = 1;

#ifdef DEBUG
    sig = de_ctx->sig_list;
    while (sig != NULL) {
        printf("sid: %d\n", sig->id);
        sig = sig->next;
    }
#endif

    sig = de_ctx->sig_list;

    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif

void SCSigRegisterSignatureOrderingTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCSigOrderingTest01", SCSigOrderingTest01);
    UtRegisterTest("SCSigOrderingTest02", SCSigOrderingTest02);
    UtRegisterTest("SCSigOrderingTest03", SCSigOrderingTest03);
    UtRegisterTest("SCSigOrderingTest04", SCSigOrderingTest04);
    UtRegisterTest("SCSigOrderingTest05", SCSigOrderingTest05);
    UtRegisterTest("SCSigOrderingTest06", SCSigOrderingTest06);
    UtRegisterTest("SCSigOrderingTest07", SCSigOrderingTest07);
    UtRegisterTest("SCSigOrderingTest08", SCSigOrderingTest08);
    UtRegisterTest("SCSigOrderingTest09", SCSigOrderingTest09);
    UtRegisterTest("SCSigOrderingTest10", SCSigOrderingTest10);
    UtRegisterTest("SCSigOrderingTest11", SCSigOrderingTest11);
    UtRegisterTest("SCSigOrderingTest12", SCSigOrderingTest12);
    UtRegisterTest("SCSigOrderingTest13", SCSigOrderingTest13);
#endif
}
