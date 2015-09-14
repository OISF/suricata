/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** \file
 *
 *  \author David DIALLO <diallo@et.esiea.fr>
 *
 *  Based on detect-engine-dns.c
 */

#include "suricata-common.h"

#include "app-layer.h"

#include "detect.h"
#include "detect-cipservice.h"

#include "detect-engine-enip.h"

#include "flow.h"

#include "util-debug.h"



int CIPPathMatch(CIPServiceEntry *svc, DetectCipServiceData *cipserviced)
{

    uint16_t class = 0;
    uint16_t attrib = 0;
    int found_class = 0;

    SegmentEntry *seg = NULL;
    TAILQ_FOREACH(seg, &svc->segment_list, next)
    {
        switch(seg->segment)
        {
            case PATH_CLASS_8BIT:
            class = seg->value;
            if (cipserviced->cipclass == class)
            {
                if (cipserviced->tokens == 2)
                {// if rule only has class
                    return 1;
                } else
                {
                    found_class = 1;
                }
            }
            break;
            case PATH_INSTANCE_8BIT:
            break;
            case PATH_ATTR_8BIT: //single attribute
            attrib = seg->value;
            if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                            == class) && (cipserviced->cipattribute == attrib) && (cipserviced->matchattribute == 1))
            { // if rule has class & attribute, matched all here
                return 1;
            }
            if ((cipserviced->tokens == 3) && (cipserviced->cipclass
                            == class) && (cipserviced->matchattribute == 0))
            { // for negation rule on attribute
                return 1;
            }
            break;
            case PATH_CLASS_16BIT:
            class = seg->value;
            if (cipserviced->cipclass == class)
            {
                if (cipserviced->tokens == 2)
                {// if rule only has class
                    return 1;
                } else
                {
                    found_class = 1;
                }
            }
            break;
            case PATH_INSTANCE_16BIT:
            break;
            default:
            SCLogDebug(
                    "CIPPathMatchAL: UNKNOWN SEGMENT 0x%x service 0x%x\n",
                    segment, node->service);
            return 0;
        }
    }

    if (found_class == 0)
    { // if haven't matched class yet, no need to check attribute
        return 0;
    }

    if ((svc->service == CIP_SET_ATTR_LIST) || (svc->service
            == CIP_GET_ATTR_LIST))
    {
        AttributeEntry *attr = NULL;
TAILQ_FOREACH    (attr, &svc->attrib_list, next)
    {
        if (cipserviced->cipattribute == attr->attribute)
        {
            return 1;
        }
    }
}

return 0;
}

int CIPServiceMatch(ENIPTransaction *enip_data,
        DetectCipServiceData *cipserviced)
{

    int count = 1;
    CIPServiceEntry *svc = NULL;
    //printf("CIPServiceMatchAL\n");
    TAILQ_FOREACH(svc, &enip_data->service_list, next)
    {
        //printf("CIPServiceMatchAL service #%d : 0x%x\n", count, svc->service);
        if (cipserviced->cipservice == svc->service)
        { // compare service
            //SCLogDebug("Rule Match for cip service %d\n",cipserviced->cipservice );
            if (cipserviced->tokens > 1)
            { //if rule params have class and attribute


                if ((svc->service == CIP_SET_ATTR_LIST) || (svc->service
                                == CIP_SET_ATTR_SINGLE) || (svc->service
                                == CIP_GET_ATTR_LIST) || (svc->service
                                == CIP_GET_ATTR_SINGLE))
                { //decode path
                    if (CIPPathMatch(svc, cipserviced) == 1)
                    {
                        return 1;
                    }
                }
            } else
            {
                // printf("CIPServiceMatchAL found\n");
                return 1;
            }
        }
        count++;
    }
    return 0;
}



/** \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx   Detection engine context
 *  \param det_ctx  Detection engine thread context
 *  \param s        Signature to inspect ( and sm: SigMatch to inspect)
 *  \param f        Flow
 *  \param flags    App layer flags
 *  \param alstate  App layer state
 *  \param txv      Pointer to ENIP Transaction structure
 *
 *  \retval 0 no match or 1 match
 */
int DetectEngineInspectENIP(ThreadVars            *tv,
                              DetectEngineCtx       *de_ctx,
                              DetectEngineThreadCtx *det_ctx,
                              Signature             *s,
                              Flow                  *f,
                              uint8_t               flags,
                              void                  *alstate,
                              void                  *txv,
                              uint64_t              tx_id)
{
    SCEnter();

//    printf("DetectEngineInspectENIP\n");

    ENIPTransaction   *tx = (ENIPTransaction *)txv;
    SigMatch            *sm = s->sm_lists[DETECT_SM_LIST_ENIP_MATCH];
    DetectCipServiceData        *cipserviced = (DetectCipServiceData *) sm->ctx;

    int ret = 0;

    if (cipserviced == NULL) {
        SCLogDebug("no cipservice state, no match");
        SCReturnInt(0);
    }

    if (CIPServiceMatch(tx, cipserviced) == 1)
            {
                SCLogDebug("DetectCIPServiceMatchAL found\n");
                SCReturnInt(1);
            }


   SCReturnInt(0);
}

#ifdef UNITTESTS /* UNITTESTS */
#include "app-layer-parser.h"

#include "detect-parse.h"

#include "detect-engine.h"

#include "flow-util.h"

#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"



/** \test Test code function. */
static int DetectEngineInspecENIPTest01(void)
{
    int result = 0;

    return result;
}


#endif /* UNITTESTS */

void DetectEngineInspectENIPRegisterTests(void)
{
#ifdef UNITTESTS
  //  UtRegisterTest("DetectEngineInspectENIPTest01", DetectEngineInspectENIPTest01, 1);
#endif /* UNITTESTS */
    return;
}
