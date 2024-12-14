/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef SURICATA_OUTPUT_H
#define SURICATA_OUTPUT_H

#include "decode.h"
#include "tm-modules.h"

#define DEFAULT_LOG_MODE_APPEND     "yes"
#define DEFAULT_LOG_FILETYPE        "regular"

typedef struct OutputLoggerThreadStore_ {
    void *thread_data;
    struct OutputLoggerThreadStore_ *next;
} OutputLoggerThreadStore;

#include "output-packet.h"
#include "output-tx.h"
#include "output-file.h"
#include "output-filedata.h"
#include "output-flow.h"
#include "output-streaming.h"
#include "output-stats.h"

typedef struct OutputInitResult_ {
    OutputCtx *ctx;
    bool ok;
} OutputInitResult;

typedef OutputInitResult (*OutputInitFunc)(ConfNode *);
typedef OutputInitResult (*OutputInitSubFunc)(ConfNode *, OutputCtx *);
typedef TmEcode (*OutputLogFunc)(ThreadVars *, Packet *, void *);
typedef TmEcode (*OutputFlushFunc)(ThreadVars *, Packet *, void *);
typedef uint32_t (*OutputGetActiveCountFunc)(void);

typedef struct OutputModule_ {
    LoggerId logger_id;
    const char *name;
    const char *conf_name;
    const char *parent_name;
    OutputInitFunc InitFunc;
    OutputInitSubFunc InitSubFunc;

    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;

    PacketLogger PacketLogFunc;
    PacketLogger PacketFlushFunc;
    PacketLogCondition PacketConditionFunc;
    TxLogger TxLogFunc;
    TxLoggerCondition TxLogCondition;
    SCFileLogger FileLogFunc;
    SCFiledataLogger FiledataLogFunc;
    FlowLogger FlowLogFunc;
    SCStreamingLogger StreamingLogFunc;
    StatsLogger StatsLogFunc;
    AppProto alproto;
    enum SCOutputStreamingType stream_type;
    int tc_log_progress;
    int ts_log_progress;

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;

/* struct for packet module and packet sub-module registration */
typedef struct OutputPacketLoggerFunctions_ {
    PacketLogger LogFunc;
    PacketLogger FlushFunc;
    PacketLogCondition ConditionFunc;
    ThreadInitFunc ThreadInitFunc;
    ThreadDeinitFunc ThreadDeinitFunc;
    ThreadExitPrintStatsFunc ThreadExitPrintStatsFunc;
} OutputPacketLoggerFunctions;

typedef TAILQ_HEAD(OutputModuleList_, OutputModule_) OutputModuleList;
extern OutputModuleList output_modules;

void OutputRegisterModule(const char *, const char *, OutputInitFunc);

void OutputRegisterPacketModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, OutputPacketLoggerFunctions *);
void OutputRegisterPacketSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, OutputPacketLoggerFunctions *);

void OutputRegisterTxModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);
void OutputRegisterTxSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

void OutputRegisterTxModuleWithCondition(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);
void OutputRegisterTxSubModuleWithCondition(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

void OutputRegisterTxModuleWithProgress(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, int tc_log_progress,
        int ts_log_progress, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);
void OutputRegisterTxSubModuleWithProgress(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        int tc_log_progress, int ts_log_progress, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);

void OutputRegisterFileSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, SCFileLogger FileLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

void OutputRegisterFiledataModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, SCFiledataLogger FiledataLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);

void OutputRegisterFlowSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, FlowLogger FlowLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

void OutputRegisterStreamingModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, SCStreamingLogger StreamingLogFunc,
        enum SCOutputStreamingType stream_type, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);

void OutputRegisterStatsModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, StatsLogger StatsLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit);
void OutputRegisterStatsSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, StatsLogger StatsLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

OutputModule *OutputGetModuleByConfName(const char *name);
void OutputDeregisterAll(void);

int OutputDropLoggerEnable(void);
void OutputDropLoggerDisable(void);

void OutputRegisterFileRotationFlag(int *flag);
void OutputUnregisterFileRotationFlag(int *flag);
void OutputNotifyFileRotation(void);

void OutputRegisterRootLogger(ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
        OutputLogFunc LogFunc, OutputGetActiveCountFunc ActiveCntFunc);
void TmModuleLoggerRegister(void);

TmEcode OutputLoggerLog(ThreadVars *, Packet *, void *);
TmEcode OutputLoggerThreadInit(ThreadVars *, const void *, void **);
TmEcode OutputLoggerThreadDeinit(ThreadVars *, void *);
void OutputLoggerExitPrintStats(ThreadVars *, void *);

void OutputSetupActiveLoggers(void);
void OutputClearActiveLoggers(void);

typedef bool (*EveJsonSimpleTxLogFunc)(void *, struct JsonBuilder *);

typedef struct EveJsonSimpleAppLayerLogger {
    EveJsonSimpleTxLogFunc LogTx;
    const char *name;
} EveJsonSimpleAppLayerLogger;

EveJsonSimpleAppLayerLogger *SCEveJsonSimpleGetLogger(AppProto alproto);

#endif /* ! SURICATA_OUTPUT_H */
