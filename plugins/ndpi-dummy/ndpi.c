/* Copyright (C) 2024 Open Information Security Foundation
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

/* License note: While this "glue" code to the nDPI library is GPLv2,
 * nDPI is itself LGPLv3 which is known to be incompatible with the
 * GPLv2. */

#include "suricata-common.h"
#include "suricata-plugin.h"

#include "detect-engine-helper.h"
#include "detect-parse.h"
#include "flow-callbacks.h"
#include "flow-storage.h"
#include "output-eve.h"
#include "thread-callbacks.h"
#include "thread-storage.h"
#include "util-debug.h"

#include "ndpi_api.h"

static ThreadStorageId thread_storage_id = { .id = -1 };
static FlowStorageId flow_storage_id = { .id = -1 };
static int ndpi_risk_keyword_id = -1;

struct NdpiThreadContext {
    struct ndpi_detection_module_struct *ndpi;
};

struct NdpiFlowContext {
    struct ndpi_flow_struct *ndpi;
    ndpi_protocol detect_l7_protocol;
    uint8_t detection_completed;
};

static void ThreadStorageFree(void *ptr)
{
    SCLogNotice("Free'ing nDPI thread storage");
    struct NdpiThreadContext *context = ptr;
    ndpi_exit_detection_module(context->ndpi);
    SCFree(context);
}

static void FlowStorageFree(void *ptr)
{
    struct NdpiFlowContext *ctx = ptr;
    ndpi_flow_free(ctx->ndpi);
    SCFree(ctx);
}

static void OnFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *_data)
{
    struct NdpiFlowContext *flowctx = SCCalloc(1, sizeof(*flowctx));
    if (flowctx == NULL) {
        FatalError("Failed to allocate nDPI flow context");
    }

    flowctx->ndpi = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (flowctx->ndpi == NULL) {
        FatalError("Failed to allocate nDPI flow");
    }

    memset(flowctx->ndpi, 0, SIZEOF_FLOW_STRUCT);
    flowctx->detection_completed = 0;
    FlowSetStorageById(f, flow_storage_id, flowctx);
}

static void OnFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *_data)
{
    struct NdpiThreadContext *threadctx = ThreadGetStorageById(tv, thread_storage_id);
    struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);

    if (threadctx->ndpi && flowctx->ndpi) {
        SCLogNotice("Performing nDPI detection...");
    }
}

static void OnFlowFinish(ThreadVars *tv, Flow *f, void *_data)
{
    /* Nothing to do here, the storage API has taken care of cleaning
     * up storage, just here for example purposes. */
    SCLogNotice("Flow %p is now finished", f);
}

static void OnThreadInit(ThreadVars *tv, void *_data)
{
    struct NdpiThreadContext *context = SCCalloc(1, sizeof(*context));
    if (context == NULL) {
        FatalError("Failed to allocate nDPI thread context");
    }
    context->ndpi = ndpi_init_detection_module(NULL);
    if (context->ndpi == NULL) {
        FatalError("Failed to initialize nDPI detection module");
    }
    NDPI_PROTOCOL_BITMASK protos;
    NDPI_BITMASK_SET_ALL(protos);
    ndpi_set_protocol_detection_bitmask2(context->ndpi, &protos);
    ndpi_finalize_initialization(context->ndpi);
    ThreadSetStorageById(tv, thread_storage_id, context);
}

static void EveCallback(ThreadVars *tv, const Packet *p, Flow *f, JsonBuilder *jb, void *data)
{
    SCLogNotice("EveCallback: tv=%p, p=%p, f=%p", tv, p, f);
    jb_open_object(jb, "ndpi");
    jb_set_bool(jb, "packet", p == NULL ? false : true);
    jb_set_bool(jb, "flow", f == NULL ? false : true);

    if (f) {
        struct NdpiFlowContext *flowctx = FlowGetStorageById(f, flow_storage_id);
        if (flowctx->ndpi->risk) {
            // ...
        }
    }

    jb_close(jb);
}

static int DetectnDPIRiskPacketMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCLogNotice("...");
    return 0;
}

static int DetectnDPIRiskSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SCLogNotice("...");
    SigMatchAppendSMToList(de_ctx, s, ndpi_risk_keyword_id, NULL, DETECT_SM_LIST_MATCH);
    return 0;
}

static void NdpInitRiskKeyword(void)
{
    /* SCSigTableElmt and DetectHelperKeywordRegister don't yet
     * support all the fields required to register the nDPI keywords,
     * so we'll just register with an empty keyword specifier to get
     * the ID, then fill in the ID. */
    SCSigTableElmt keyword = {};
    ndpi_risk_keyword_id = DetectHelperKeywordRegister(&keyword);
    SCLogNotice("Registered new keyword with ID %" PRIu32, ndpi_risk_keyword_id);

    sigmatch_table[ndpi_risk_keyword_id].name = "ndpi-risk";
    sigmatch_table[ndpi_risk_keyword_id].desc = "match on the detected nDPI risk";
    sigmatch_table[ndpi_risk_keyword_id].url = "/rules/ndpi-risk.html";
    sigmatch_table[ndpi_risk_keyword_id].Match = DetectnDPIRiskPacketMatch;
    sigmatch_table[ndpi_risk_keyword_id].Setup = DetectnDPIRiskSetup;
}

static void NdpiInit(void)
{
    SCLogNotice("Initializing nDPI plugin");

    /* Register thread storage. */
    thread_storage_id = ThreadStorageRegister("ndpi", sizeof(void *), NULL, ThreadStorageFree);
    if (thread_storage_id.id < 0) {
        FatalError("Failed to register nDPI thread storage");
    }

    /* Register flow storage. */
    flow_storage_id = FlowStorageRegister("ndpi", sizeof(void *), NULL, FlowStorageFree);
    if (flow_storage_id.id < 0) {
        FatalError("Failed to register nDPI flow storage");
    }

    /* Register flow lifecycle callbacks. */
    SCFlowRegisterInitCallback(OnFlowInit, NULL);
    SCFlowRegisterUpdateCallback(OnFlowUpdate, NULL);

    /* Not needed for nDPI, but exists for completeness. */
    SCFlowRegisterFinishCallback(OnFlowFinish, NULL);

    /* Register thread init callback. */
    SCThreadRegisterInitCallback(OnThreadInit, NULL);

    /* Register an EVE callback. */
    SCEveRegisterCallback(EveCallback, NULL);

    NdpInitRiskKeyword();
}

const SCPlugin PluginRegistration = {
    .name = "ndpi-dummy",
    .author = "FirstName LastName",
    .license = "GPLv2",
    .Init = NdpiInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
