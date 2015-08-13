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
   // ENIPData   *tx = (ENIPData *)txv;
   // SigMatch            *sm = s->sm_lists[DETECT_SM_LIST_ENIP_MATCH];
   // DetectCipServiceData        *cipserviced = (DetectCipServiceData *) sm->ctx;

    int ret = 0;

    printf("DetectEngineInspectENIP\n");

 //   if (cipserviced == NULL) {
 //       SCLogDebug("no cipservice state, no match");
 //       SCReturnInt(0);
 //   }

   ret = 1;

   SCReturnInt(ret);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

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
