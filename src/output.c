/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author OISF, Jason Ish <jason.ish@oisf.net>
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 *
 * The root logging output for all non-application logging.
 *
 * The loggers are made up of a hierarchy of loggers. At the top we
 * have the root logger which is the main entry point to
 * logging. Under the root there exists parent loggers that are the
 * entry point for specific types of loggers such as packet logger,
 * transaction loggers, etc. Each parent logger may have 0 or more
 * loggers that actual handle the job of producing output to something
 * like a file.
 */

#include "suricata-common.h"
#include "flow.h"
#include "conf.h"
#include "tm-threads.h"
#include "util-error.h"
#include "util-debug.h"
#include "output.h"

#include "alert-fastlog.h"
#include "alert-debuglog.h"
#include "alert-syslog.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-anomaly.h"
#include "output-json-flow.h"
#include "output-json-netflow.h"
#include "log-cf-common.h"
#include "output-json-drop.h"
#include "log-httplog.h"
#include "output-json-http.h"
#include "output-json-dns.h"
#include "output-json-modbus.h"
#include "log-tlslog.h"
#include "log-tlsstore.h"
#include "output-json-tls.h"
#include "output-json-ssh.h"
#include "log-pcap.h"
#include "output-json-file.h"
#include "output-json-smtp.h"
#include "output-json-stats.h"
#include "log-tcp-data.h"
#include "log-stats.h"
#include "output-json-nfs.h"
#include "output-json-ftp.h"
#include "output-json-tftp.h"
#include "output-json-smb.h"
#include "output-json-ike.h"
#include "output-json-krb5.h"
#include "output-json-quic.h"
#include "output-json-dhcp.h"
#include "output-json-snmp.h"
#include "output-json-sip.h"
#include "output-json-rfb.h"
#include "output-json-mqtt.h"
#include "output-json-pgsql.h"
#include "output-json-template.h"
#include "output-json-template-rust.h"
#include "output-json-rdp.h"
#include "output-json-http2.h"
#include "output-lua.h"
#include "output-json-dnp3.h"
#include "output-json-metadata.h"
#include "output-json-dcerpc.h"
#include "output-json-frame.h"
#include "output-json-bittorrent-dht.h"
#include "output-filestore.h"

typedef struct RootLogger_ {
    OutputLogFunc LogFunc;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
    OutputGetActiveCountFunc ActiveCntFunc;

    TAILQ_ENTRY(RootLogger_) entries;
} RootLogger;

/* List of registered root loggers. These are registered at start up and
 * are independent of configuration. Later we will build a list of active
 * loggers based on configuration. */
static TAILQ_HEAD(, RootLogger_) registered_loggers =
    TAILQ_HEAD_INITIALIZER(registered_loggers);

/* List of active root loggers. This means that at least one logger is enabled
 * for each root logger type in the config. */
static TAILQ_HEAD(, RootLogger_) active_loggers =
    TAILQ_HEAD_INITIALIZER(active_loggers);

typedef struct LoggerThreadStoreNode_ {
    void *thread_data;
    TAILQ_ENTRY(LoggerThreadStoreNode_) entries;
} LoggerThreadStoreNode;

typedef TAILQ_HEAD(LoggerThreadStore_, LoggerThreadStoreNode_) LoggerThreadStore;

/**
 * The list of all registered (known) output modules.
 */
OutputModuleList output_modules = TAILQ_HEAD_INITIALIZER(output_modules);

/**
 * Registry of flags to be updated on file rotation notification.
 */
typedef struct OutputFileRolloverFlag_ {
    int *flag;

    TAILQ_ENTRY(OutputFileRolloverFlag_) entries;
} OutputFileRolloverFlag;

TAILQ_HEAD(, OutputFileRolloverFlag_) output_file_rotation_flags =
    TAILQ_HEAD_INITIALIZER(output_file_rotation_flags);

void OutputRegisterRootLoggers(void);
void OutputRegisterLoggers(void);

/**
 * \brief Register an output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterModule(const char *name, const char *conf_name,
    OutputInitFunc InitFunc)
{
    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL))
        goto error;

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Output module \"%s\" registered.", name);

    return;

error:
    FatalError(SC_ERR_FATAL,
               "Fatal error encountered in OutputRegisterModule. Exiting...");
}

/**
 * \brief Register a packet output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterPacketModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc,
    PacketLogger PacketLogFunc, PacketLogCondition PacketConditionFunc,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(PacketLogFunc == NULL || PacketConditionFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->PacketLogFunc = PacketLogFunc;
    module->PacketConditionFunc = PacketConditionFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a packet output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterPacketSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    PacketLogger PacketLogFunc, PacketLogCondition PacketConditionFunc,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(PacketLogFunc == NULL || PacketConditionFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->PacketLogFunc = PacketLogFunc;
    module->PacketConditionFunc = PacketConditionFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Wrapper function for tx output modules.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
static void OutputRegisterTxModuleWrapper(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, AppProto alproto,
    TxLogger TxLogFunc, int tc_log_progress, int ts_log_progress,
    TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(TxLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->TxLogFunc = TxLogFunc;
    module->TxLogCondition = TxLogCondition;
    module->alproto = alproto;
    module->tc_log_progress = tc_log_progress;
    module->ts_log_progress = ts_log_progress;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

static void OutputRegisterTxSubModuleWrapper(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    AppProto alproto, TxLogger TxLogFunc, int tc_log_progress,
    int ts_log_progress, TxLoggerCondition TxLogCondition,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(TxLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->TxLogFunc = TxLogFunc;
    module->TxLogCondition = TxLogCondition;
    module->alproto = alproto;
    module->tc_log_progress = tc_log_progress;
    module->ts_log_progress = ts_log_progress;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger for alproto %d \"%s\" registered.", alproto, name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a tx output module with condition.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModuleWithCondition(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, AppProto alproto,
    TxLogger TxLogFunc, TxLoggerCondition TxLogCondition,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto,
        TxLogFunc, -1, -1, TxLogCondition, ThreadInit, ThreadDeinit,
        ThreadExitPrintStats);
}

void OutputRegisterTxSubModuleWithCondition(LoggerId id,
    const char *parent_name, const char *name, const char *conf_name,
    OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
    TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name, InitFunc,
        alproto, TxLogFunc, -1, -1, TxLogCondition, ThreadInit, ThreadDeinit,
        ThreadExitPrintStats);
}

/**
 * \brief Register a tx output module with progress.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModuleWithProgress(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, AppProto alproto,
    TxLogger TxLogFunc, int tc_log_progress, int ts_log_progress,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto,
        TxLogFunc, tc_log_progress, ts_log_progress, NULL, ThreadInit,
        ThreadDeinit, ThreadExitPrintStats);
}

void OutputRegisterTxSubModuleWithProgress(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    AppProto alproto, TxLogger TxLogFunc, int tc_log_progress,
    int ts_log_progress, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name, InitFunc,
        alproto, TxLogFunc, tc_log_progress, ts_log_progress, NULL, ThreadInit,
        ThreadDeinit, ThreadExitPrintStats);
}

/**
 * \brief Register a tx output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, AppProto alproto,
    TxLogger TxLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto,
        TxLogFunc, -1, -1, NULL, ThreadInit, ThreadDeinit,
        ThreadExitPrintStats);
}

void OutputRegisterTxSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name,
    OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name,
        InitFunc, alproto, TxLogFunc, -1, -1, NULL, ThreadInit, ThreadDeinit,
        ThreadExitPrintStats);
}

/**
 * \brief Register a file output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFileModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, FileLogger FileLogFunc,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(FileLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->FileLogFunc = FileLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("File logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a file output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFileSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    FileLogger FileLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(FileLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FileLogFunc = FileLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("File logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a file data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFiledataModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc,
    FiledataLogger FiledataLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(FiledataLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->FiledataLogFunc = FiledataLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Filedata logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a file data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFiledataSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    FiledataLogger FiledataLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(FiledataLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FiledataLogFunc = FiledataLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Filedata logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a flow output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFlowSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    FlowLogger FlowLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(FlowLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FlowLogFunc = FlowLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Flow logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a streaming data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStreamingModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc,
    StreamingLogger StreamingLogFunc,
    enum OutputStreamingType stream_type, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(StreamingLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->StreamingLogFunc = StreamingLogFunc;
    module->stream_type = stream_type;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Streaming logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a streaming data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStreamingSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    StreamingLogger StreamingLogFunc, enum OutputStreamingType stream_type,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(StreamingLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->StreamingLogFunc = StreamingLogFunc;
    module->stream_type = stream_type;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Streaming logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a stats data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStatsModule(LoggerId id, const char *name,
    const char *conf_name, OutputInitFunc InitFunc, StatsLogger StatsLogFunc,
    ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(StatsLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->StatsLogFunc = StatsLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Register a stats data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStatsSubModule(LoggerId id, const char *parent_name,
    const char *name, const char *conf_name, OutputInitSubFunc InitFunc,
    StatsLogger StatsLogFunc, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    if (unlikely(StatsLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->logger_id = id;
    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->StatsLogFunc = StatsLogFunc;
    module->ThreadInit = ThreadInit;
    module->ThreadDeinit = ThreadDeinit;
    module->ThreadExitPrintStats = ThreadExitPrintStats;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    FatalError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
}

/**
 * \brief Get an output module by name.
 *
 * \retval The OutputModule with the given name or NULL if no output module
 * with the given name is registered.
 */
OutputModule *OutputGetModuleByConfName(const char *conf_name)
{
    OutputModule *module;

    TAILQ_FOREACH(module, &output_modules, entries) {
        if (strcmp(module->conf_name, conf_name) == 0)
            return module;
    }

    return NULL;
}

/**
 * \brief Deregister all modules.  Useful for a memory clean exit.
 */
void OutputDeregisterAll(void)
{
    OutputModule *module;

    while ((module = TAILQ_FIRST(&output_modules))) {
        TAILQ_REMOVE(&output_modules, module, entries);
        SCFree(module);
    }
}

static int drop_loggers = 0;

int OutputDropLoggerEnable(void)
{
    if (drop_loggers)
        return -1;
    drop_loggers++;
    return 0;
}

void OutputDropLoggerDisable(void)
{
    if (drop_loggers)
        drop_loggers--;
}

/**
 * \brief Register a flag for file rotation notification.
 *
 * \param flag A pointer that will be set to 1 when file rotation is
 *   requested.
 */
void OutputRegisterFileRotationFlag(int *flag)
{
    OutputFileRolloverFlag *flag_entry = SCCalloc(1, sizeof(*flag_entry));
    if (unlikely(flag_entry == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate memory to register file rotation flag");
        return;
    }
    flag_entry->flag = flag;
    TAILQ_INSERT_TAIL(&output_file_rotation_flags, flag_entry, entries);
}

/**
 * \brief Unregister a file rotation flag.
 *
 * Note that it is safe to call this function with a flag that may not
 * have been registered, in which case this function won't do
 * anything.
 *
 * \param flag A pointer that has been previously registered for file
 *   rotation notifications.
 */
void OutputUnregisterFileRotationFlag(int *flag)
{
    OutputFileRolloverFlag *entry, *next;
    for (entry = TAILQ_FIRST(&output_file_rotation_flags); entry != NULL;
         entry = next) {
        next = TAILQ_NEXT(entry, entries);
        if (entry->flag == flag) {
            TAILQ_REMOVE(&output_file_rotation_flags, entry, entries);
            SCFree(entry);
            break;
        }
    }
}

/**
 * \brief Notifies all registered file rotation notification flags.
 */
void OutputNotifyFileRotation(void) {
    OutputFileRolloverFlag *flag;
    TAILQ_FOREACH(flag, &output_file_rotation_flags, entries) {
        *(flag->flag) = 1;
    }
}

TmEcode OutputLoggerLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        logger->LogFunc(tv, p, thread_store_node->thread_data);

        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }
    return TM_ECODE_OK;
}

TmEcode OutputLoggerThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    LoggerThreadStore *thread_store = SCCalloc(1, sizeof(*thread_store));
    if (thread_store == NULL) {
        return TM_ECODE_FAILED;
    }
    TAILQ_INIT(thread_store);
    *data = (void *)thread_store;

    RootLogger *logger;
    TAILQ_FOREACH(logger, &active_loggers, entries) {

        void *child_thread_data = NULL;
        if (logger->ThreadInit != NULL) {
            if (logger->ThreadInit(tv, initdata, &child_thread_data) == TM_ECODE_OK) {
                LoggerThreadStoreNode *thread_store_node =
                    SCCalloc(1, sizeof(*thread_store_node));
                if (thread_store_node == NULL) {
                    /* Undo everything, calling de-init will take care
                     * of that. */
                    OutputLoggerThreadDeinit(tv, thread_store);
                    return TM_ECODE_FAILED;
                }
                thread_store_node->thread_data = child_thread_data;
                TAILQ_INSERT_TAIL(thread_store, thread_store_node, entries);
            }
        }
    }
    return TM_ECODE_OK;
}

TmEcode OutputLoggerThreadDeinit(ThreadVars *tv, void *thread_data)
{
    if (thread_data == NULL)
        return TM_ECODE_FAILED;

    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        if (logger->ThreadDeinit != NULL) {
            logger->ThreadDeinit(tv, thread_store_node->thread_data);
        }
        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }

    /* Free the thread store. */
    while ((thread_store_node = TAILQ_FIRST(thread_store)) != NULL) {
        TAILQ_REMOVE(thread_store, thread_store_node, entries);
        SCFree(thread_store_node);
    }
    SCFree(thread_store);

    return TM_ECODE_OK;
}

void OutputLoggerExitPrintStats(ThreadVars *tv, void *thread_data)
{
    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        if (logger->ThreadExitPrintStats != NULL) {
            logger->ThreadExitPrintStats(tv, thread_store_node->thread_data);
        }
        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }
}

void OutputRegisterRootLogger(ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats,
    OutputLogFunc LogFunc, OutputGetActiveCountFunc ActiveCntFunc)
{
    BUG_ON(LogFunc == NULL);

    RootLogger *logger = SCCalloc(1, sizeof(*logger));
    if (logger == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to alloc root logger");
    }
    logger->ThreadInit = ThreadInit;
    logger->ThreadDeinit = ThreadDeinit;
    logger->ThreadExitPrintStats = ThreadExitPrintStats;
    logger->LogFunc = LogFunc;
    logger->ActiveCntFunc = ActiveCntFunc;
    TAILQ_INSERT_TAIL(&registered_loggers, logger, entries);
}

static void OutputRegisterActiveLogger(RootLogger *reg)
{
    RootLogger *logger = SCCalloc(1, sizeof(*logger));
    if (logger == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to alloc root logger");
    }
    logger->ThreadInit = reg->ThreadInit;
    logger->ThreadDeinit = reg->ThreadDeinit;
    logger->ThreadExitPrintStats = reg->ThreadExitPrintStats;
    logger->LogFunc = reg->LogFunc;
    logger->ActiveCntFunc = reg->ActiveCntFunc;
    TAILQ_INSERT_TAIL(&active_loggers, logger, entries);
}

void OutputSetupActiveLoggers(void)
{
    RootLogger *logger = TAILQ_FIRST(&registered_loggers);
    while (logger) {
        uint32_t cnt = logger->ActiveCntFunc();
        if (cnt) {
            OutputRegisterActiveLogger(logger);
        }

        logger = TAILQ_NEXT(logger, entries);
    }
}

void OutputClearActiveLoggers(void)
{
    RootLogger *logger;
    while ((logger = TAILQ_FIRST(&active_loggers)) != NULL) {
        TAILQ_REMOVE(&active_loggers, logger, entries);
        SCFree(logger);
    }
}

void TmModuleLoggerRegister(void)
{
    OutputRegisterRootLoggers();
    OutputRegisterLoggers();
}

/**
 * \brief Register all root loggers.
 */
void OutputRegisterRootLoggers(void)
{
    OutputPacketLoggerRegister();
    OutputFiledataLoggerRegister();
    OutputFileLoggerRegister();
    OutputTxLoggerRegister();
    OutputStreamingLoggerRegister();
}

/**
 * \brief Register all non-root logging modules.
 */
void OutputRegisterLoggers(void)
{
    /* custom format log*/
    LogCustomFormatRegister();

    LuaLogRegister();
    /* fast log */
    AlertFastLogRegister();
    /* debug log */
    AlertDebugLogRegister();
    /* syslog log */
    AlertSyslogRegister();
    JsonDropLogRegister();
    /* json log */
    OutputJsonRegister();
    /* email logs */
    JsonSmtpLogRegister();
    /* http log */
    LogHttpLogRegister();
    JsonHttpLogRegister();
    JsonHttp2LogRegister();
    /* tls log */
    LogTlsLogRegister();
    JsonTlsLogRegister();
    LogTlsStoreRegister();
    /* ssh */
    JsonSshLogRegister();
    /* pcap log */
    PcapLogRegister();
    /* file log */
    JsonFileLogRegister();
    OutputFilestoreRegister();
    /* dns */
    JsonDnsLogRegister();
    /* modbus */
    JsonModbusLogRegister();
    /* tcp streaming data */
    LogTcpDataLogRegister();
    /* log stats */
    LogStatsLogRegister();

    JsonAlertLogRegister();
    JsonAnomalyLogRegister();
    /* flow/netflow */
    JsonFlowLogRegister();
    JsonNetFlowLogRegister();
    /* json stats */
    JsonStatsLogRegister();

    /* DNP3. */
    JsonDNP3LogRegister();
    JsonMetadataLogRegister();

    /* NFS JSON logger. */
    JsonNFSLogRegister();
    /* TFTP JSON logger. */
    JsonTFTPLogRegister();
    /* FTP JSON logger. */
    JsonFTPLogRegister();
    /* SMB JSON logger. */
    JsonSMBLogRegister();
    /* IKE JSON logger. */
    JsonIKELogRegister();
    /* KRB5 JSON logger. */
    JsonKRB5LogRegister();
    /* QUIC JSON logger. */
    JsonQuicLogRegister();
    /* DHCP JSON logger. */
    JsonDHCPLogRegister();
    /* SNMP JSON logger. */
    JsonSNMPLogRegister();
    /* SIP JSON logger. */
    JsonSIPLogRegister();
    /* RFB JSON logger. */
    JsonRFBLogRegister();
    /* MQTT JSON logger. */
    JsonMQTTLogRegister();
    /* Pgsql JSON logger. */
    JsonPgsqlLogRegister();
    /* Template JSON logger. */
    JsonTemplateLogRegister();
    /* Template Rust JSON logger. */
    JsonTemplateRustLogRegister();
    /* RDP JSON logger. */
    JsonRdpLogRegister();
    /* DCERPC JSON logger. */
    JsonDCERPCLogRegister();
    /* app layer frames */
    JsonFrameLogRegister();
    /* BitTorrent DHT JSON logger */
    JsonBitTorrentDHTLogRegister();
}
