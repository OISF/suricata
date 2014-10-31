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
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "suricata.h"
#include "tm-threads.h"

#define DEFAULT_LOG_MODE_APPEND     "yes"
#define DEFAULT_LOG_FILETYPE        "regular"

#include "output-packet.h"
#include "output-tx.h"
#include "output-file.h"
#include "output-filedata.h"
#include "output-flow.h"
#include "output-streaming.h"
#include "output-stats.h"

typedef struct OutputModule_ {
    const char *name;
    const char *conf_name;
    const char *parent_name;
    OutputCtx *(*InitFunc)(ConfNode *);
    OutputCtx *(*InitSubFunc)(ConfNode *, OutputCtx *parent_ctx);

    PacketLogger PacketLogFunc;
    PacketLogCondition PacketConditionFunc;
    TxLogger TxLogFunc;
    FileLogger FileLogFunc;
    FiledataLogger FiledataLogFunc;
    FlowLogger FlowLogFunc;
    StreamingLogger StreamingLogFunc;
    StatsLogger StatsLogFunc;
    AppProto alproto;
    enum OutputStreamingType stream_type;

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;

void OutputRegisterModule(const char *, const char *, OutputCtx *(*)(ConfNode *));

void OutputRegisterPacketModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *),
    PacketLogger LogFunc, PacketLogCondition ConditionFunc);
void OutputRegisterPacketSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    PacketLogger LogFunc, PacketLogCondition ConditionFunc);

void OutputRegisterTxModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), AppProto alproto,
    TxLogger TxLogFunc);
void OutputRegisterTxSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *parent_ctx),
    AppProto alproto, TxLogger TxLogFunc);

void OutputRegisterFileModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FileLogger FileLogFunc);
void OutputRegisterFileSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FileLogger FileLogFunc);

void OutputRegisterFiledataModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FiledataLogger FiledataLogFunc);
void OutputRegisterFiledataSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FiledataLogger FiledataLogFunc);

void OutputRegisterFlowModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FlowLogger FlowLogFunc);
void OutputRegisterFlowSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FlowLogger FlowLogFunc);

void OutputRegisterStreamingModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), StreamingLogger StreamingLogFunc,
    enum OutputStreamingType stream_type);
void OutputRegisterStreamingSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    StreamingLogger StreamingLogFunc, enum OutputStreamingType stream_type);

void OutputRegisterStatsModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), StatsLogger StatsLogFunc);
void OutputRegisterStatsSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    StatsLogger StatsLogFunc);

OutputModule *OutputGetModuleByConfName(const char *name);
void OutputDeregisterAll(void);

int OutputDropLoggerEnable(void);
void OutputDropLoggerDisable(void);

int OutputTlsLoggerEnable(void);
void OutputTlsLoggerDisable(void);

int OutputSshLoggerEnable(void);
void OutputSshLoggerDisable(void);

void OutputRegisterFileRotationFlag(int *flag);
void OutputUnregisterFileRotationFlag(int *flag);
void OutputNotifyFileRotation(void);

#endif /* ! __OUTPUT_H__ */
