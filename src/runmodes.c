/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Pre-cooked threading runmodes.
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "tm-threads.h"
#include "util-time.h"

int RunModeIdsPcap(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

   ThreadVars *tv_unified2 = TmThreadCreatePacketHandler("Unified2Alert","alert-queue3","simple","alert-queue4","simple","1slot");
    if (tv_unified2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_unified2,tm_module,au2a_logfile_ctx);

    if (TmThreadSpawn(tv_unified2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue4","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module, ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pcap mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPcap2(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

   ThreadVars *tv_unified2 = TmThreadCreatePacketHandler("Unified2Alert","alert-queue3","simple","alert-queue4","simple","1slot");
    if (tv_unified2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_unified2,tm_module,au2a_logfile_ctx);

    if (TmThreadSpawn(tv_unified2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue4","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module, ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pcap mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPcap3(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,au2a_logfile_ctx);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, ad_logfile_ctx);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,au2a_logfile_ctx);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, ad_logfile_ctx);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,au2a_logfile_ctx);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, ad_logfile_ctx);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,au2a_logfile_ctx);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, ad_logfile_ctx);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int RunModeIpsNFQ(DetectEngineCtx *de_ctx, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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
    Tm1SlotSetFunc(tv_receivenfq,tm_module,NULL);

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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

   ThreadVars *tv_unified2 = TmThreadCreatePacketHandler("Unified2Alert","alert-queue3","simple","alert-queue4","simple","1slot");
    if (tv_unified2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_unified2,tm_module,au2a_logfile_ctx);

    if (TmThreadSpawn(tv_unified2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue4","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module, ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int RunModeFilePcap(DetectEngineCtx *de_ctx, char *file, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert,tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified2 = TmThreadCreatePacketHandler("Unified2Alert","alert-queue3","simple","alert-queue4","simple","1slot");
    if (tv_unified2 == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_unified2,tm_module,au2a_logfile_ctx);

    if (TmThreadSpawn(tv_unified2) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue4","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module, ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcap2(DetectEngineCtx *de_ctx, char *file, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("Unified2Alert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for Unified2Alert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,au2a_logfile_ctx);
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module, ad_logfile_ctx);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int RunModeIdsPfring(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified, tm_module, aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue3","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module,ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

/** \brief Live pfring mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPfring2(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    ThreadVars *tv_alert = TmThreadCreatePacketHandler("AlertFastlog&Httplog","alert-queue1","simple","alert-queue2","simple","varslot");
    if (tv_alert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_alert, tm_module, lh_logfile_ctx);

    if (TmThreadSpawn(tv_alert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_unified = TmThreadCreatePacketHandler("AlertUnifiedLog","alert-queue2","simple","alert-queue3","simple","varslot");
    if (tv_unified == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv_unified,tm_module,aua_logfile_ctx);

    if (TmThreadSpawn(tv_unified) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    ThreadVars *tv_debugalert = TmThreadCreatePacketHandler("AlertDebuglog","alert-queue3","simple","packetpool","packetpool","1slot");
    if (tv_debugalert == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(EXIT_FAILURE);
    }
    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_debugalert,tm_module,ad_logfile_ctx);

    if (TmThreadSpawn(tv_debugalert) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}
/** \brief Live pfring mode with 4 stream tracking and reassembly threads, testing the flow queuehandler */
int RunModeIdsPfring3(DetectEngineCtx *de_ctx, char *iface, LogFileCtx *af_logfile_ctx, LogFileCtx *ad_logfile_ctx, LogFileCtx *lh_logfile_ctx, LogFileCtx *aul_logfile_ctx, LogFileCtx *aua_logfile_ctx, LogFileCtx *au2a_logfile_ctx) {
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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,af_logfile_ctx);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,lh_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aul_logfile_ctx);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,aua_logfile_ctx);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

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

    tm_module = TmModuleGetByName("AlertFastlog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertFastlog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("LogHttplog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedLog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedLog failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertUnifiedAlert");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName for AlertUnifiedAlert failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,NULL);

    tm_module = TmModuleGetByName("AlertDebuglog");
    if (tm_module == NULL) {
        printf("ERROR: TmModuleGetByName failed\n");
        exit(EXIT_FAILURE);
    }
    TmVarSlotSetFuncAppend(tv,tm_module,ad_logfile_ctx);

    TmThreadSetCPUAffinity(tv, 1);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}
