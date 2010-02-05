/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Pre-cooked threading runmodes.
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-time.h"
#include "conf.h"
#include "queue.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "output.h"

/**
 * A list of output modules that will be active for the run mode.
 */
typedef struct RunModeOutput_ {
    TmModule *tm_module;
    LogFileCtx *logfile_ctx;

    TAILQ_ENTRY(RunModeOutput_) entries;
} RunModeOutput;
TAILQ_HEAD(, RunModeOutput_) RunModeOutputs =
    TAILQ_HEAD_INITIALIZER(RunModeOutputs);

/**
 * Cleanup the run mode.
 */
void RunModeShutDown(void)
{
    /* Close any log files. */
    RunModeOutput *output;
    while ((output = TAILQ_FIRST(&RunModeOutputs))) {
        SCLogDebug("Shutting down output %s.", output->tm_module->name);
        TAILQ_REMOVE(&RunModeOutputs, output, entries);
        if (output->logfile_ctx != NULL)
            LogFileFreeCtx(output->logfile_ctx);
        free(output);
    }
}

/**
 * Initialize the output modules.
 */
void RunModeInitializeOutputs(void)
{
    ConfNode *outputs = ConfGetNode("outputs");
    if (outputs == NULL) {
        /* No "outputs" section in the configuration. */
        return;
    }

    ConfNode *output, *output_config;
    TmModule *tm_module;
    const char *enabled;

    TAILQ_FOREACH(output, &outputs->head, next) {

        OutputModule *module = OutputGetModuleByConfName(output->val);
        if (module == NULL) {
            SCLogWarning(SC_INVALID_ARGUMENT,
                "No output module named %s, ignoring", output->val);
            continue;
        }

        output_config = ConfNodeLookupChild(output, module->conf_name);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            SCLogError(SC_INVALID_ARGUMENT,
                "Failed to lookup configuration child node: fast");
            exit(1);
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled != NULL && strcasecmp(enabled, "yes") == 0) {
            LogFileCtx *logfile_ctx = module->InitFunc(output_config);
            if (logfile_ctx == NULL) {
                /* In most cases the init function will have logged the
                 * error. Maybe we should exit on init errors? */
                continue;
            }
            tm_module = TmModuleGetByName(module->name);
            if (tm_module == NULL) {
                SCLogError(SC_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", module->name);
                exit(EXIT_FAILURE);
            }
            RunModeOutput *runmode_output = calloc(1, sizeof(RunModeOutput));
            if (runmode_output == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory for output.");
                exit(EXIT_FAILURE);
            }
            runmode_output->tm_module = tm_module;
            runmode_output->logfile_ctx = logfile_ctx;
            TAILQ_INSERT_TAIL(&RunModeOutputs, runmode_output, entries);
        }
    }
}

/**
 * Setup the outputs for this run mode.
 *
 * \param tv The ThreadVars for the thread the outputs will be
 * appended to.
 */
static void SetupOutputs(ThreadVars *tv)
{
    RunModeOutput *output;
    TAILQ_FOREACH(output, &RunModeOutputs, entries) {
        TmVarSlotSetFuncAppend(tv, output->tm_module, output->logfile_ctx);
    }
}

int RunModeIdsPcap(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler("ReceivePcap","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pcap mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPcap2(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler("ReceivePcap","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1,decode-queue2,decode-queue3,decode-queue4","flow","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream2 = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","stream-queue1","simple","1slot");
    if (tv_stream2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream2\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream2,tm_module,NULL);

    if (TmThreadSpawn(tv_stream2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream3 = TmThreadCreatePacketHandler("Stream3","decode-queue3","simple","stream-queue2","simple","1slot");
    if (tv_stream3 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream3,tm_module,NULL);

    if (TmThreadSpawn(tv_stream3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream4 = TmThreadCreatePacketHandler("Stream4","decode-queue4","simple","stream-queue2","simple","1slot");
    if (tv_stream4 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream4,tm_module,NULL);

    if (TmThreadSpawn(tv_stream4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue2","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs1 = TmThreadCreatePacketHandler("Outputs1",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs1);
    if (TmThreadSpawn(tv_outputs1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pcap mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPcap3(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler("ReceivePcap","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1,decode-queue2,decode-queue3,decode-queue4","flow","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePcap");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv;
    tv = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    /* In this mode we don't create a new thread for alerting/logging.
     * We'll pass the one currently being setup and the alerting
     * modules will be appended to it. */
    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 0);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 0);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream3","decode-queue3","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream4","decode-queue4","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int RunModeIpsNFQ(DetectEngineCtx *de_ctx, char *nfq_id) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivenfq = TmThreadCreatePacketHandler("ReceiveNFQ","packetpool","packetpool","pickup-queue","simple","1slot_noinout");
    if (tv_receivenfq == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveNFQ\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivenfq,tm_module,nfq_id);

    if (TmThreadSpawn(tv_receivenfq) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodeNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeNFQ failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_verdict = TmThreadCreatePacketHandler("Verdict","verdict-queue","simple","respond-queue","simple","1slot");
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("VerdictNFQ");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName VerdictNFQ failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_verdict,tm_module,nfq_id);

    if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","respond-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int RunModeFilePcap(DetectEngineCtx *de_ctx, char *file) {
    printf("RunModeFilePcap: file %s\n", file);
    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv_receivepcap = TmThreadCreatePacketHandler("ReceivePcapFile","packetpool","packetpool","pickup-queue","simple","1slot");
    if (tv_receivepcap == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepcap,tm_module,file);

    if (TmThreadSpawn(tv_receivepcap) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
//#if 0
    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","alert-queue1","simple","1slot");
//#endif
    //ThreadVars *tv_detect1 = TmThreadCreate("Detect1","decode-queue1","simple","alert-queue1","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue1","simple","alert-queue1","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcap2(DetectEngineCtx *de_ctx, char *file) {
    printf("RunModeFilePcap2: file %s\n", file);
    TimeModeSetOffline();

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler("PcapFile","packetpool","packetpool","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePcap\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePcap failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    SetupOutputs(tv);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int RunModeIdsPfring(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepfring = TmThreadCreatePacketHandler("ReceivePfring","packetpool","packetpool","pickup-queue1","simple","1slot");
    if (tv_receivepfring == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_receivepfring2 = TmThreadCreatePacketHandler("ReceivePfring2","packetpool","packetpool","pickup-queue2","simple","1slot");
    if (tv_receivepfring2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring2,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue1","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode2 = TmThreadCreatePacketHandler("Decode2","pickup-queue2","simple","decode-queue2","simple","1slot");
    if (tv_decode2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode2,tm_module,NULL);

    if (TmThreadSpawn(tv_decode2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream2 = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","stream-queue2","simple","1slot");
    if (tv_stream2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream2,tm_module,NULL);

    if (TmThreadSpawn(tv_stream2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue2","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pfring mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPfring2(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepfring = TmThreadCreatePacketHandler("ReceivePfring","packetpool","packetpool","pickup-queue","simple","1slot");
    if (tv_receivepfring == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1,decode-queue2,decode-queue3,decode-queue4","flow","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream2 = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","stream-queue1","simple","1slot");
    if (tv_stream2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream2\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream2,tm_module,NULL);

    if (TmThreadSpawn(tv_stream2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream3 = TmThreadCreatePacketHandler("Stream3","decode-queue3","simple","stream-queue2","simple","1slot");
    if (tv_stream3 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream3,tm_module,NULL);

    if (TmThreadSpawn(tv_stream3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream4 = TmThreadCreatePacketHandler("Stream4","decode-queue4","simple","stream-queue2","simple","1slot");
    if (tv_stream4 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream4,tm_module,NULL);

    if (TmThreadSpawn(tv_stream4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue2","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
/** \brief Live pfring mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPfring3(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepfring = TmThreadCreatePacketHandler("ReceivePfring","packetpool","packetpool","pickup-queue","simple","1slot");
    if (tv_receivepfring == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1,decode-queue2,decode-queue3,decode-queue4","flow","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv;
    tv = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 0);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 0);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream3","decode-queue3","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv = TmThreadCreatePacketHandler("Stream4","decode-queue4","simple","packetpool","packetpool","varslot");
    if (tv == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,(void *)de_ctx);

    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    SetupOutputs(tv);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int RunModeIpsIPFW(DetectEngineCtx *de_ctx) {

    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receiveipfw = TmThreadCreatePacketHandler("ReceiveIPFW","packetpool","packetpool","pickup-queue","simple","1slot_noinout");

    if (tv_receiveipfw == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceiveIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceiveIPFW\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receiveipfw,tm_module,NULL);

    if (TmThreadSpawn(tv_receiveipfw) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodeIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodeIPFW failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_verdict = TmThreadCreatePacketHandler("Verdict","verdict-queue","simple","respond-queue","simple","1slot");
    if (tv_verdict == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("VerdictIPFW");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName VerdictIPFW failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_verdict,tm_module,NULL);

    if (TmThreadSpawn(tv_verdict) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","respond-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** RunmodeIdsPfring4 simple 4 pfring, decode, stream, and detect threads */
int RunModeIdsPfring4(DetectEngineCtx *de_ctx, char *iface) {
    TimeModeSetLive();

    /* create the threads */
    ThreadVars *tv_receivepfring = TmThreadCreatePacketHandler("ReceivePfring","packetpool","packetpool","pickup-queue1","simple","1slot");
    if (tv_receivepfring == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    TmModule *tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_receivepfring2 = TmThreadCreatePacketHandler("ReceivePfring2","packetpool","packetpool","pickup-queue2","simple","1slot");
    if (tv_receivepfring2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring2,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_receivepfring3 = TmThreadCreatePacketHandler("ReceivePfring3","packetpool","packetpool","pickup-queue3","simple","1slot");
    if (tv_receivepfring3 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring3,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_receivepfring4 = TmThreadCreatePacketHandler("ReceivePfring4","packetpool","packetpool","pickup-queue4","simple","1slot");
    if (tv_receivepfring4 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("ReceivePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed for ReceivePfring\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_receivepfring4,tm_module,(void *)iface);

    if (TmThreadSpawn(tv_receivepfring4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode1 = TmThreadCreatePacketHandler("Decode1","pickup-queue1","simple","decode-queue1","simple","1slot");
    if (tv_decode1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode1,tm_module,NULL);

    if (TmThreadSpawn(tv_decode1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode2 = TmThreadCreatePacketHandler("Decode2","pickup-queue2","simple","decode-queue2","simple","1slot");
    if (tv_decode2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode2,tm_module,NULL);

    if (TmThreadSpawn(tv_decode2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode3 = TmThreadCreatePacketHandler("Decode3","pickup-queue3","simple","decode-queue3","simple","1slot");
    if (tv_decode3 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode3,tm_module,NULL);

    if (TmThreadSpawn(tv_decode3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_decode4 = TmThreadCreatePacketHandler("Decode4","pickup-queue4","simple","decode-queue4","simple","1slot");
    if (tv_decode4 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Decode1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("DecodePfring");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName DecodePfring failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_decode4,tm_module,NULL);

    if (TmThreadSpawn(tv_decode4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream1 = TmThreadCreatePacketHandler("Stream1","decode-queue1","simple","stream-queue1","simple","1slot");
    if (tv_stream1 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream1,tm_module,NULL);

    if (TmThreadSpawn(tv_stream1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream2 = TmThreadCreatePacketHandler("Stream2","decode-queue2","simple","stream-queue2","simple","1slot");
    if (tv_stream2 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream2,tm_module,NULL);
    if (TmThreadSpawn(tv_stream2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream3 = TmThreadCreatePacketHandler("Stream3","decode-queue3","simple","stream-queue3","simple","1slot");
    if (tv_stream3 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream3,tm_module,NULL);

    if (TmThreadSpawn(tv_stream3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_stream4 = TmThreadCreatePacketHandler("Stream4","decode-queue4","simple","stream-queue4","simple","1slot");
    if (tv_stream4 == NULL) {
        printf("ERROR: TmThreadsCreate failed for Stream1\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("StreamTcp");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName StreamTcp failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_stream4,tm_module,NULL);

    if (TmThreadSpawn(tv_stream4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect1 = TmThreadCreatePacketHandler("Detect1","stream-queue1","simple","verdict-queue","simple","1slot");
    if (tv_detect1 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect1,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect1) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    ThreadVars *tv_detect2 = TmThreadCreatePacketHandler("Detect2","stream-queue2","simple","verdict-queue","simple","1slot");
    if (tv_detect2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect2,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect3 = TmThreadCreatePacketHandler("Detect3","stream-queue3","simple","verdict-queue","simple","1slot");
    if (tv_detect3 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect3,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect3) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_detect4= TmThreadCreatePacketHandler("Detect4","stream-queue4","simple","verdict-queue","simple","1slot");
    if (tv_detect4 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Detect");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName Detect failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_detect4,tm_module,(void *)de_ctx);

    if (TmThreadSpawn(tv_detect4) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_rreject = TmThreadCreatePacketHandler("RespondReject","verdict-queue","simple","alert-queue1","simple","1slot");
    if (tv_rreject == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("RespondReject");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for RespondReject failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_rreject,tm_module,NULL);

    if (TmThreadSpawn(tv_rreject) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_outputs = TmThreadCreatePacketHandler("Outputs",
        "alert-queue1", "simple", "packetpool", "packetpool", "varslot");
    SetupOutputs(tv_outputs);
    if (TmThreadSpawn(tv_outputs) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

