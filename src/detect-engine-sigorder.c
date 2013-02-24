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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Signature ordering part of the detection engine.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-flowbits.h"
#include "detect-flowint.h"
#include "detect-engine-sigorder.h"
#include "detect-pcre.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-action.h"
#include "action-globals.h"

#define DETECT_FLOWVAR_NOT_USED   1
#define DETECT_FLOWVAR_TYPE_READ  2
#define DETECT_FLOWVAR_TYPE_SET   3

#define DETECT_PKTVAR_NOT_USED   1
#define DETECT_PKTVAR_TYPE_READ  2
#define DETECT_PKTVAR_TYPE_SET   3

#define DETECT_FLOWBITS_NOT_USED  1
#define DETECT_FLOWBITS_TYPE_READ 2
#define DETECT_FLOWBITS_TYPE_SET  3

#define DETECT_FLOWINT_NOT_USED  1
#define DETECT_FLOWINT_TYPE_READ 2
#define DETECT_FLOWINT_TYPE_SET  3


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
    prev = curr;
    while (curr != NULL) {
        prev = curr;
        if (curr->SWCompare == SWCompare)
            break;

        curr = curr->next;
    }

    if (curr != NULL)
        return;

    if ( (temp = SCMalloc(sizeof(SCSigOrderFunc))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in SCSigRegisterSignatureOrderingFunc. Exiting...");
        exit(EXIT_FAILURE);
    }
    memset(temp, 0, sizeof(SCSigOrderFunc));

    temp->SWCompare = SWCompare;

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
    SigMatch *sm = sig->sm_lists[DETECT_SM_LIST_MATCH];
    DetectFlowbitsData *fb = NULL;
    int flowbits = DETECT_FLOWBITS_CMD_MAX;
    int flowbits_user_type = DETECT_FLOWBITS_NOT_USED;

    while (sm != NULL) {
        if (sm->type == DETECT_FLOWBITS) {
            fb = (DetectFlowbitsData *)sm->ctx;
            if (flowbits > fb->cmd)
                flowbits = fb->cmd;
        }

        sm = sm->next;
    }

    sm = sig->sm_lists[DETECT_SM_LIST_POSTMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_FLOWBITS) {
            fb = (DetectFlowbitsData *)sm->ctx;
            if (flowbits > fb->cmd)
                flowbits = fb->cmd;
        }

        sm = sm->next;
    }

    if (flowbits == DETECT_FLOWBITS_CMD_SET ||
        flowbits == DETECT_FLOWBITS_CMD_UNSET ||
        flowbits == DETECT_FLOWBITS_CMD_TOGGLE) {
        flowbits_user_type = DETECT_FLOWBITS_TYPE_SET;
    } else if (flowbits == DETECT_FLOWBITS_CMD_ISNOTSET ||
               flowbits == DETECT_FLOWBITS_CMD_ISSET ||
               flowbits == DETECT_FLOWBITS_CMD_NOALERT) {
        flowbits_user_type = DETECT_FLOWBITS_TYPE_READ;
    }

    SCLogDebug("Sig %s typeval %d", sig->msg, flowbits_user_type);

    return flowbits_user_type;
}

static inline int SCSigGetFlowintType(Signature *sig)
{
    SigMatch *sm = sig->sm_lists[DETECT_SM_LIST_MATCH];
    DetectFlowintData *fi = NULL;
    int modifier = FLOWINT_MODIFIER_UNKNOWN;
    int flowint_user_type = DETECT_FLOWINT_NOT_USED;

    while (sm != NULL) {
        if (sm->type == DETECT_FLOWINT) {
            fi = (DetectFlowintData *)sm->ctx;
            if (modifier > fi->modifier)
                modifier = fi->modifier;
        }

        sm = sm->next;
    }

    sm = sig->sm_lists[DETECT_SM_LIST_POSTMATCH];
    while (sm != NULL) {
        if (sm->type == DETECT_FLOWINT) {
            fi = (DetectFlowintData *)sm->ctx;
            if (modifier > fi->modifier)
                modifier = fi->modifier;
        }

        sm = sm->next;
    }

    if (modifier == FLOWINT_MODIFIER_SET ||
        modifier == FLOWINT_MODIFIER_ADD ||
        modifier == FLOWINT_MODIFIER_SUB) {
        flowint_user_type = DETECT_FLOWINT_TYPE_SET;
    } else if (modifier == FLOWINT_MODIFIER_LT ||
               modifier == FLOWINT_MODIFIER_LE ||
               modifier == FLOWINT_MODIFIER_EQ ||
               modifier == FLOWINT_MODIFIER_NE ||
               modifier == FLOWINT_MODIFIER_GE ||
               modifier == FLOWINT_MODIFIER_GT ||
               modifier == FLOWINT_MODIFIER_ISSET) {
        flowint_user_type = DETECT_FLOWINT_TYPE_READ;
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
    SigMatch *sm = sig->sm_lists[DETECT_SM_LIST_PMATCH];
    DetectPcreData *pd = NULL;
    int type = DETECT_FLOWVAR_NOT_USED;

    while (sm != NULL) {
        pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_PCRE && (pd->flags & DETECT_PCRE_CAPTURE_FLOW)) {
            type = DETECT_FLOWVAR_TYPE_SET;
            return type;
        }

        sm = sm->next;
    }

    sm = sig->sm_lists[DETECT_SM_LIST_MATCH];
    pd = NULL;
    while (sm != NULL) {
        //pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_FLOWVAR) {
            type = DETECT_FLOWVAR_TYPE_READ;
            return type;
        }

        sm = sm->next;
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
    SigMatch *sm = sig->sm_lists[DETECT_SM_LIST_PMATCH];
    DetectPcreData *pd = NULL;
    int type = DETECT_PKTVAR_NOT_USED;

    while (sm != NULL) {
        pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_PCRE && (pd->flags & DETECT_PCRE_CAPTURE_PKT)) {
            type = DETECT_PKTVAR_TYPE_SET;
            return type;
        }

        sm = sm->next;
    }

    sm = sig->sm_lists[DETECT_SM_LIST_MATCH];
    pd = NULL;
    while (sm != NULL) {
        //pd = (DetectPcreData *)sm->ctx;
        if (sm->type == DETECT_PKTVAR) {
            type = DETECT_PKTVAR_TYPE_READ;
            return type;
        }

        sm = sm->next;
    }

    return type;
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
    *((int *)(sw->user[SC_RADIX_USER_DATA_FLOWBITS])) = SCSigGetFlowbitsType(sw->sig);

    return;
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
    *((int *)(sw->user[SC_RADIX_USER_DATA_FLOWVAR])) = SCSigGetFlowvarType(sw->sig);

    return;
}

static inline void SCSigProcessUserDataForFlowint(SCSigSignatureWrapper *sw)
{
    *((int *)(sw->user[SC_RADIX_USER_DATA_FLOWINT])) = SCSigGetFlowintType(sw->sig);

    return;
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
    *((int *)(sw->user[SC_RADIX_USER_DATA_PKTVAR])) = SCSigGetPktvarType(sw->sig);

    return;
}

static void SCSigOrder(DetectEngineCtx *de_ctx,
                       SCSigSignatureWrapper *sw,
                       int (*SWCompare)(SCSigSignatureWrapper *sw1, SCSigSignatureWrapper *sw2))
{
    SCSigSignatureWrapper *min = NULL;
    SCSigSignatureWrapper *max = NULL;
    SCSigSignatureWrapper *prev = NULL;

    if (sw == NULL)
        return;

    if (de_ctx->sc_sig_sig_wrapper == NULL) {
        de_ctx->sc_sig_sig_wrapper = sw;
        sw->min = NULL;
        sw->max = NULL;
        return;
    }

    min = sw->min;
    max = sw->max;
    if (min == NULL)
        min = de_ctx->sc_sig_sig_wrapper;
    else
        min = min->next;

    while (min != max) {
        prev = min;
        /* the sorting logic */
        if (SWCompare(sw, min) <= 0) {
            min = min->next;
            continue;
        }

        if (min->prev == sw)
            break;

        if (sw->next != NULL)
            sw->next->prev = sw->prev;
        if (sw->prev != NULL)
            sw->prev->next = sw->next;
        if (de_ctx->sc_sig_sig_wrapper == sw)
            de_ctx->sc_sig_sig_wrapper = sw->next;

        sw->next = min;
        sw->prev = min->prev;

        if (min->prev != NULL)
            min->prev->next = sw;
        else
            de_ctx->sc_sig_sig_wrapper = sw;

        min->prev = sw;

        break;
    }

    if (min == max && prev != sw) {
        if (sw->next != NULL) {
            sw->next->prev = sw->prev;
        }
        if (sw->prev != NULL) {
            sw->prev->next = sw->next;
        }

        if (min == NULL) {
            if (prev != NULL)
                prev->next = sw;
            sw->prev = prev;
            sw->next = NULL;
        } else {
            sw->prev = min->prev;
            sw->next = min;
            if (min->prev != NULL)
                min->prev->next = sw;
            min->prev = sw;
        }
    }

    /* set the min signature for this keyword, for the next ordering function */
    min = sw;
    while (min != NULL && min != sw->min) {
        if (SWCompare(sw, min) != 0)
            break;

        min = min->prev;
    }
    sw->min = min;

    /* set the max signature for this keyword + 1, for the next ordering func */
    max = sw;
    while (max != NULL && max != sw->max) {
        if (SWCompare(max, sw) != 0)
            break;

        max = max->next;
    }
    sw->max = max;

    return;
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
    return *((int *)sw1->user[SC_RADIX_USER_DATA_FLOWBITS]) -
        *((int *)sw2->user[SC_RADIX_USER_DATA_FLOWBITS]);
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
    return *((int *)sw1->user[SC_RADIX_USER_DATA_FLOWVAR]) -
        *((int *)sw2->user[SC_RADIX_USER_DATA_FLOWVAR]);
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
    return *((int *)sw1->user[SC_RADIX_USER_DATA_PKTVAR]) -
        *((int *)sw2->user[SC_RADIX_USER_DATA_PKTVAR]);
}

static int SCSigOrderByFlowintCompare(SCSigSignatureWrapper *sw1,
                                      SCSigSignatureWrapper *sw2)
{
    return *((int *)sw1->user[SC_RADIX_USER_DATA_FLOWINT]) -
        *((int *)sw2->user[SC_RADIX_USER_DATA_FLOWINT]);
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
    return sw1->sig->prio - sw2->sig->prio;
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
    int i = 0;

    if ( (sw = SCMalloc(sizeof(SCSigSignatureWrapper))) == NULL)
        return NULL;
    memset(sw, 0, sizeof(SCSigSignatureWrapper));

    sw->sig = sig;

    if ( (sw->user = SCMalloc(SC_RADIX_USER_DATA_MAX * sizeof(int *))) == NULL) {
        SCFree(sw);
        return NULL;
    }
    memset(sw->user, 0, SC_RADIX_USER_DATA_MAX * sizeof(int *));

    for (i = 0; i < SC_RADIX_USER_DATA_MAX; i++) {
        if ( (sw->user[i] = SCMalloc(sizeof(int))) == NULL) {
            SCFree(sw);
            return NULL;
        }
        memset(sw->user[i], 0, sizeof(int));
    }

    /* Process data from the signature into a cache for further use by the
     * sig_ordering module */
    SCSigProcessUserDataForFlowbits(sw);
    SCSigProcessUserDataForFlowvar(sw);
    SCSigProcessUserDataForFlowint(sw);
    SCSigProcessUserDataForPktvar(sw);

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
    SCSigOrderFunc *funcs = NULL;
    Signature *sig = NULL;
    SCSigSignatureWrapper *sigw = NULL;

    int i = 0;
    SCLogDebug("ordering signatures in memory");

    sig = de_ctx->sig_list;
    while (sig != NULL) {
        i++;
        sigw = SCSigAllocSignatureWrapper(sig);
        funcs = de_ctx->sc_sig_order_funcs;
        while (funcs != NULL) {
            SCSigOrder(de_ctx, sigw, funcs->SWCompare);

            funcs = funcs->next;
        }
        sig = sig->next;
    }

    SCLogDebug("Total Signatures to be processed by the"
           "sigordering module: %d", i);

    /* Re-order it in the Detection Engine Context sig_list */
    de_ctx->sig_list = NULL;
    sigw = de_ctx->sc_sig_sig_wrapper;
    i = 0;
    while (sigw != NULL) {
        i++;
        if (de_ctx->sig_list == NULL) {
            sigw->sig->next = NULL;
            de_ctx->sig_list = sigw->sig;
            sig = de_ctx->sig_list;
            sigw = sigw->next;
            continue;
        }

        sigw->sig->next = NULL;
        sig->next = sigw->sig;
        sig = sig->next;
        sigw = sigw->next;
    }

    SCLogDebug("total signatures reordered by the sigordering module: %d", i);
    return;
}

/**
 * \brief Lets you register the Signature ordering functions.  The order in
 *        which the functions are registered, show the priority.  The first
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
    SCSigRegisterSignatureOrderingFunc(de_ctx, SCSigOrderByPriorityCompare);

    return;
}

/**
 * \brief De-registers all the signature ordering functions registered
 *
 * \param de_ctx Pointer to the detection engine context from which the
 *               signatures were ordered.
 */
void SCSigSignatureOrderingModuleCleanup(DetectEngineCtx *de_ctx)
{
    SCSigOrderFunc *funcs = NULL;
    SCSigSignatureWrapper *sigw = NULL;
    SCSigSignatureWrapper *prev = NULL;
    void *temp = NULL;
    uint8_t i;

    /* clean the memory alloted to the signature ordering funcs */
    funcs = de_ctx->sc_sig_order_funcs;
    while (funcs != NULL) {
        temp = funcs;
        funcs = funcs->next;
        SCFree(temp);
    }
    de_ctx->sc_sig_order_funcs = NULL;

    /* clean the memory alloted to the signature wrappers */
    sigw = de_ctx->sc_sig_sig_wrapper;
    while (sigw != NULL) {
        prev = sigw;
        sigw = sigw->next;
        for (i = 0; i < SC_RADIX_USER_DATA_MAX; i++) {
            if (prev->user[i] != NULL) {
                SCFree(prev->user[i]);
            }
        }
        SCFree(prev->user);
        SCFree(prev);
    }
    de_ctx->sc_sig_sig_wrapper = NULL;

    return;
}

/**********Unittests**********/

DetectEngineCtx *DetectEngineCtxInit(void);
Signature *SigInit(DetectEngineCtx *, char *);
void SigFree(Signature *);
void DetectEngineCtxFree(DetectEngineCtx *);

#ifdef UNITTESTS

static int SCSigTestSignatureOrdering01(void)
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

static int SCSigTestSignatureOrdering02(void)
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

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:2;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; sid:3;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; flowvar:http_host,\"www.oisf.net\"; rev:4; priority:1; sid:4;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:1; sid:5;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; pcre:\"/^User-Agent: (?P<flow_http_host>.*)\\r\\n/m\"; content:\"220\"; offset:10; depth:4; rev:4; priority:3; sid:6;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:7;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; sid:8;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;


    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:10; depth:4; pcre:\"/^User-Agent: (?P<pkt_http_host>.*)\\r\\n/m\"; rev:4; priority:3; flowbits:set,TEST.one; flowbits:noalert; sid:9;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "pass tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:11; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:3; sid:10;)");
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

    sig = SigInit(de_ctx, "drop tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; pktvar:http_host,\"www.oisf.net\"; priority:2; flowbits:isnotset,TEST.two; sid:13;)");
    if (sig == NULL) {
        goto end;
    }
    prevsig->next = sig;
    prevsig = sig;

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"Testing sigordering\"; content:\"220\"; offset:12; depth:4; pcre:\"/220[- ]/\"; rev:4; priority:2; flowbits:set,TEST.two; sid:14;)");
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

    /* pass */
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 10);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;

    /* drops */
    result &= (sig->id == 9);
    sig = sig->next;
    result &= (sig->id == 13);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;

    /* alerts */
    result &= (sig->id == 14);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 11);
    sig = sig->next;
    result &= (sig->id == 12);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigTestSignatureOrdering03(void)
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
    result &= (sig->id == 9);
    sig = sig->next;
    result &= (sig->id == 8);
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
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 10);
    sig = sig->next;
    result &= (sig->id == 11);
    sig = sig->next;
    result &= (sig->id == 12);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 5);
    sig = sig->next;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigTestSignatureOrdering04(void)
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

static int SCSigTestSignatureOrdering05(void)
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
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 7);
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

static int SCSigTestSignatureOrdering06(void)
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
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;


end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SCSigTestSignatureOrdering07(void)
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
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 8);
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
static int SCSigTestSignatureOrdering08(void)
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
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 2);
    sig = sig->next;
    result &= (sig->id == 4);
    sig = sig->next;
    result &= (sig->id == 5);
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
static int SCSigTestSignatureOrdering09(void)
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

    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 6);
    sig = sig->next;
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 8);
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
static int SCSigTestSignatureOrdering10(void)
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
    result &= (sig->id == 1);
    sig = sig->next;
    result &= (sig->id == 3);
    sig = sig->next;
    result &= (sig->id == 8);
    sig = sig->next;
    result &= (sig->id == 7);
    sig = sig->next;
    result &= (sig->id == 6);
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

static int SCSigTestSignatureOrdering11(void)
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

#endif

void SCSigRegisterSignatureOrderingTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCSigTestSignatureOrdering01", SCSigTestSignatureOrdering01, 1);
    UtRegisterTest("SCSigTestSignatureOrdering02", SCSigTestSignatureOrdering02, 1);
    UtRegisterTest("SCSigTestSignatureOrdering03", SCSigTestSignatureOrdering03, 1);
    UtRegisterTest("SCSigTestSignatureOrdering04", SCSigTestSignatureOrdering04, 1);
    UtRegisterTest("SCSigTestSignatureOrdering05", SCSigTestSignatureOrdering05, 1);
    UtRegisterTest("SCSigTestSignatureOrdering06", SCSigTestSignatureOrdering06, 1);
    UtRegisterTest("SCSigTestSignatureOrdering07", SCSigTestSignatureOrdering07, 1);
    UtRegisterTest("SCSigTestSignatureOrdering08", SCSigTestSignatureOrdering08, 1);
    UtRegisterTest("SCSigTestSignatureOrdering09", SCSigTestSignatureOrdering09, 1);
    UtRegisterTest("SCSigTestSignatureOrdering10", SCSigTestSignatureOrdering10, 1);
    UtRegisterTest("SCSigTestSignatureOrdering11", SCSigTestSignatureOrdering11, 1);
#endif

    return;
}
