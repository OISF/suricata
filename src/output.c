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
#include "output-eve-bindgen.h"

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
#include "output-eve-stream.h"
#include "log-httplog.h"
#include "output-json-http.h"
#include "output-json-dns.h"
#include "output-json-mdns.h"
#include "log-tlslog.h"
#include "log-tlsstore.h"
#include "output-json-tls.h"
#include "log-pcap.h"
// for SSHTxLogCondition
#include "app-layer-ssh.h"
#include "output-json-file.h"
#include "output-json-smtp.h"
#include "output-json-stats.h"
#include "log-tcp-data.h"
#include "log-stats.h"
#include "output-json-nfs.h"
#include "output-json-ftp.h"
// for misplaced EveFTPDataAddMetadata
#include "app-layer-ftp.h"
#include "output-json-smb.h"
#include "output-json-ike.h"
#include "output-json-dhcp.h"
#include "output-json-mqtt.h"
#include "output-json-pgsql.h"
#include "output-lua.h"
#include "output-json-dnp3.h"
#include "output-json-metadata.h"
#include "output-json-dcerpc.h"
#include "output-json-frame.h"
#include "app-layer-parser.h"
#include "output-filestore.h"
#include "output-json-arp.h"

typedef struct RootLogger_ {
    OutputLogFunc LogFunc;
    OutputFlushFunc FlushFunc;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
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

static SCMutex output_file_rotation_mutex = SCMUTEX_INITIALIZER;

TAILQ_HEAD(, OutputFileRolloverFlag_) output_file_rotation_flags =
    TAILQ_HEAD_INITIALIZER(output_file_rotation_flags);

/**
 * Callback function to be called when logging is ready.
 */
typedef void (*SCOnLoggingReadyCallback)(void *arg);

/**
 * List entries for callbacks registered to be called when the logging system is
 * ready. This is useful for both plugins and library users who need to register
 * application transaction loggers after logging initialization is complete.
 */
typedef struct OnLoggingReadyCallbackNode_ {
    SCOnLoggingReadyCallback callback;
    void *arg;
    TAILQ_ENTRY(OnLoggingReadyCallbackNode_) entries;
} OnLoggingReadyCallbackNode;

/**
 * The list of callbacks to be called when logging is ready.
 */
static TAILQ_HEAD(, OnLoggingReadyCallbackNode_)
        on_logging_ready_callbacks = TAILQ_HEAD_INITIALIZER(on_logging_ready_callbacks);

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
    FatalError("Fatal error encountered in OutputRegisterModule. Exiting...");
}

/**
 * \brief Register a packet output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterPacketModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, OutputPacketLoggerFunctions *output_module_functions)
{
    if (unlikely(output_module_functions->LogFunc == NULL ||
                 output_module_functions->ConditionFunc == NULL)) {
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
    module->PacketLogFunc = output_module_functions->LogFunc;
    module->PacketFlushFunc = output_module_functions->FlushFunc;
    module->PacketConditionFunc = output_module_functions->ConditionFunc;
    module->ThreadInit = output_module_functions->ThreadInitFunc;
    module->ThreadDeinit = output_module_functions->ThreadDeinitFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a packet output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterPacketSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc,
        OutputPacketLoggerFunctions *output_logger_functions)
{
    if (unlikely(output_logger_functions->LogFunc == NULL ||
                 output_logger_functions->ConditionFunc == NULL)) {
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
    module->PacketLogFunc = output_logger_functions->LogFunc;
    module->PacketFlushFunc = output_logger_functions->FlushFunc;
    module->PacketConditionFunc = output_logger_functions->ConditionFunc;
    module->ThreadInit = output_logger_functions->ThreadInitFunc;
    module->ThreadDeinit = output_logger_functions->ThreadDeinitFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Wrapper function for tx output modules.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
static void OutputRegisterTxModuleWrapper(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, int tc_log_progress,
        int ts_log_progress, TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

static void OutputRegisterTxSubModuleWrapper(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        int tc_log_progress, int ts_log_progress, TxLoggerCondition TxLogCondition,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger for alproto %d \"%s\" registered.", alproto, name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a tx output module with condition.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModuleWithCondition(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto, TxLogFunc, -1, -1,
            TxLogCondition, ThreadInit, ThreadDeinit);
}

void OutputRegisterTxSubModuleWithCondition(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        TxLoggerCondition TxLogCondition, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name, InitFunc, alproto, TxLogFunc,
            -1, -1, TxLogCondition, ThreadInit, ThreadDeinit);
}

/**
 * \brief Register a tx output module with progress.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModuleWithProgress(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, int tc_log_progress,
        int ts_log_progress, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto, TxLogFunc,
            tc_log_progress, ts_log_progress, NULL, ThreadInit, ThreadDeinit);
}

void OutputRegisterTxSubModuleWithProgress(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        int tc_log_progress, int ts_log_progress, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name, InitFunc, alproto, TxLogFunc,
            tc_log_progress, ts_log_progress, NULL, ThreadInit, ThreadDeinit);
}

/**
 * \brief Register a tx output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterTxModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, AppProto alproto, TxLogger TxLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxModuleWrapper(id, name, conf_name, InitFunc, alproto, TxLogFunc, -1, -1, NULL,
            ThreadInit, ThreadDeinit);
}

void OutputRegisterTxSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, AppProto alproto, TxLogger TxLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
{
    OutputRegisterTxSubModuleWrapper(id, parent_name, name, conf_name, InitFunc, alproto, TxLogFunc,
            -1, -1, NULL, ThreadInit, ThreadDeinit);
}

/**
 * \brief Register a file output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFileSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, SCFileLogger FileLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("File logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a file data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFiledataModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, SCFiledataLogger FiledataLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Filedata logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a flow output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterFlowSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, FlowLogger FlowLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Flow logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a streaming data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStreamingModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, SCStreamingLogger StreamingLogFunc,
        enum SCOutputStreamingType stream_type, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Streaming logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a stats data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStatsModule(LoggerId id, const char *name, const char *conf_name,
        OutputInitFunc InitFunc, StatsLogger StatsLogFunc, ThreadInitFunc ThreadInit,
        ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
}

/**
 * \brief Register a stats data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void OutputRegisterStatsSubModule(LoggerId id, const char *parent_name, const char *name,
        const char *conf_name, OutputInitSubFunc InitFunc, StatsLogger StatsLogFunc,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
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
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    FatalError("Fatal error encountered. Exiting...");
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

static EveJsonSimpleAppLayerLogger *simple_json_applayer_loggers;

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
    SCFree(simple_json_applayer_loggers);
    simple_json_applayer_loggers = NULL;
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
        SCLogError("Failed to allocate memory to register file rotation flag");
        return;
    }
    flag_entry->flag = flag;
    SCMutexLock(&output_file_rotation_mutex);
    TAILQ_INSERT_TAIL(&output_file_rotation_flags, flag_entry, entries);
    SCMutexUnlock(&output_file_rotation_mutex);
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
    SCMutexLock(&output_file_rotation_mutex);
    for (entry = TAILQ_FIRST(&output_file_rotation_flags); entry != NULL;
         entry = next) {
        next = TAILQ_NEXT(entry, entries);
        if (entry->flag == flag) {
            TAILQ_REMOVE(&output_file_rotation_flags, entry, entries);
            SCMutexUnlock(&output_file_rotation_mutex);
            SCFree(entry);
            return;
        }
    }
    SCMutexUnlock(&output_file_rotation_mutex);
}

/**
 * \brief Notifies all registered file rotation notification flags.
 */
void OutputNotifyFileRotation(void) {
    OutputFileRolloverFlag *flag = NULL;
    OutputFileRolloverFlag *tflag;
    SCMutexLock(&output_file_rotation_mutex);
    TAILQ_FOREACH_SAFE (flag, &output_file_rotation_flags, entries, tflag) {
        *(flag->flag) = 1;
    }
    SCMutexUnlock(&output_file_rotation_mutex);
}

/**
 * \brief Register a callback to be called when logging is ready.
 *
 * This function registers a callback that will be invoked when the logging
 * system has been fully initialized. This is useful for both plugins and
 * library users who need to register application transaction loggers after
 * logging initialization is complete.
 *
 * \param callback The callback function to be called
 * \param arg An argument to be passed to the callback function
 * \return 0 on success, -1 on failure
 */
int SCRegisterOnLoggingReady(SCOnLoggingReadyCallback callback, void *arg)
{
    OnLoggingReadyCallbackNode *node = SCCalloc(1, sizeof(*node));
    if (node == NULL) {
        SCLogError("Failed to allocate memory for callback node");
        return -1;
    }

    node->callback = callback;
    node->arg = arg;
    TAILQ_INSERT_TAIL(&on_logging_ready_callbacks, node, entries);

    return 0;
}

/**
 * \brief Invokes all registered logging ready callbacks.
 *
 * This function should be called after the logging system has been fully
 * initialized to notify all registered callbacks that logging is ready.
 */
void SCOnLoggingReady(void)
{
    OnLoggingReadyCallbackNode *node = NULL;
    TAILQ_FOREACH (node, &on_logging_ready_callbacks, entries) {
        if (node->callback) {
            (*node->callback)(node->arg);
        }
    }
}

TmEcode OutputLoggerFlush(ThreadVars *tv, Packet *p, void *thread_data)
{
    LoggerThreadStore *thread_store = (LoggerThreadStore *)thread_data;
    RootLogger *logger = TAILQ_FIRST(&active_loggers);
    LoggerThreadStoreNode *thread_store_node = TAILQ_FIRST(thread_store);
    while (logger && thread_store_node) {
        if (logger->FlushFunc)
            logger->FlushFunc(tv, p, thread_store_node->thread_data);

        logger = TAILQ_NEXT(logger, entries);
        thread_store_node = TAILQ_NEXT(thread_store_node, entries);
    }
    return TM_ECODE_OK;
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

void OutputRegisterRootLogger(ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
        OutputLogFunc LogFunc, OutputGetActiveCountFunc ActiveCntFunc)
{
    BUG_ON(LogFunc == NULL);

    RootLogger *logger = SCCalloc(1, sizeof(*logger));
    if (logger == NULL) {
        FatalError("failed to alloc root logger");
    }
    logger->ThreadInit = ThreadInit;
    logger->ThreadDeinit = ThreadDeinit;
    logger->LogFunc = LogFunc;
    logger->ActiveCntFunc = ActiveCntFunc;
    TAILQ_INSERT_TAIL(&registered_loggers, logger, entries);
}

static void OutputRegisterActiveLogger(RootLogger *reg)
{
    RootLogger *logger = SCCalloc(1, sizeof(*logger));
    if (logger == NULL) {
        FatalError("failed to alloc root logger");
    }
    logger->ThreadInit = reg->ThreadInit;
    logger->ThreadDeinit = reg->ThreadDeinit;
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

EveJsonSimpleAppLayerLogger *SCEveJsonSimpleGetLogger(AppProto alproto)
{
    if (alproto < g_alproto_max) {
        return &simple_json_applayer_loggers[alproto];
    }
    return NULL;
}

static void RegisterSimpleJsonApplayerLogger(
        AppProto alproto, EveJsonSimpleTxLogFunc LogTx, const char *name)
{
    simple_json_applayer_loggers[alproto].LogTx = LogTx;
    if (name) {
        simple_json_applayer_loggers[alproto].name = name;
    } else {
        simple_json_applayer_loggers[alproto].name = AppProtoToString(alproto);
    }
}

/**
 * \brief Register all root loggers.
 */
void OutputRegisterRootLoggers(void)
{
    simple_json_applayer_loggers = SCCalloc(g_alproto_max, sizeof(EveJsonSimpleAppLayerLogger));
    if (unlikely(simple_json_applayer_loggers == NULL)) {
        FatalError("Failed to allocate simple_json_applayer_loggers");
    }
    // ALPROTO_HTTP1 special: uses some options flags
    RegisterSimpleJsonApplayerLogger(ALPROTO_FTP, (EveJsonSimpleTxLogFunc)EveFTPLogCommand, NULL);
    // ALPROTO_SMTP special: uses state
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_TLS, (EveJsonSimpleTxLogFunc)JsonTlsLogJSONExtended, NULL);
    // no cast here but done in rust for SSHTransaction
    RegisterSimpleJsonApplayerLogger(ALPROTO_SSH, (EveJsonSimpleTxLogFunc)SCSshLogJson, NULL);
    // ALPROTO_SMB special: uses state
    // ALPROTO_DCERPC special: uses state
    RegisterSimpleJsonApplayerLogger(ALPROTO_DNS, (EveJsonSimpleTxLogFunc)AlertJsonDns, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_MDNS, (EveJsonSimpleTxLogFunc)AlertJsonMdns, NULL);
    // either need a cast here or in rust for ModbusTransaction, done here
    RegisterSimpleJsonApplayerLogger(ALPROTO_MODBUS, (EveJsonSimpleTxLogFunc)SCModbusToJson, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_ENIP, (EveJsonSimpleTxLogFunc)SCEnipLoggerLog, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_DNP3, (EveJsonSimpleTxLogFunc)AlertJsonDnp3, NULL);
    // ALPROTO_NFS special: uses state
    // underscore instead of dash for ftp_data
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_FTPDATA, (EveJsonSimpleTxLogFunc)EveFTPDataAddMetadata, "ftp_data");
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_TFTP, (EveJsonSimpleTxLogFunc)SCTftpLogJsonRequest, NULL);
    // ALPROTO_IKE special: uses state
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_KRB5, (EveJsonSimpleTxLogFunc)SCKrb5LogJsonResponse, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_QUIC, (EveJsonSimpleTxLogFunc)SCQuicLogJson, NULL);
    // ALPROTO_DHCP TODO missing
    RegisterSimpleJsonApplayerLogger(ALPROTO_SIP, (EveJsonSimpleTxLogFunc)SCSipLogJson, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_RFB, (EveJsonSimpleTxLogFunc)SCRfbJsonLogger, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_POP3, (EveJsonSimpleTxLogFunc)SCPop3LoggerLog, NULL);
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_MQTT, (EveJsonSimpleTxLogFunc)JsonMQTTAddMetadata, NULL);
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_PGSQL, (EveJsonSimpleTxLogFunc)JsonPgsqlAddMetadata, NULL);
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_WEBSOCKET, (EveJsonSimpleTxLogFunc)SCWebSocketLoggerLog, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_LDAP, (EveJsonSimpleTxLogFunc)SCLdapLoggerLog, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_DOH2, (EveJsonSimpleTxLogFunc)AlertJsonDoh2, NULL);
    RegisterSimpleJsonApplayerLogger(
            ALPROTO_TEMPLATE, (EveJsonSimpleTxLogFunc)SCTemplateLoggerLog, NULL);
    RegisterSimpleJsonApplayerLogger(ALPROTO_RDP, (EveJsonSimpleTxLogFunc)SCRdpToJson, NULL);
    // special case : http2 is logged in http object
    RegisterSimpleJsonApplayerLogger(ALPROTO_HTTP2, (EveJsonSimpleTxLogFunc)SCHttp2LogJson, "http");
    // underscore instead of dash for bittorrent_dht
    RegisterSimpleJsonApplayerLogger(ALPROTO_BITTORRENT_DHT,
            (EveJsonSimpleTxLogFunc)SCBittorrentDhtLogger, "bittorrent_dht");

    OutputPacketLoggerRegister();
    OutputFiledataLoggerRegister();
    OutputFileLoggerRegister();
    OutputTxLoggerRegister();
    OutputStreamingLoggerRegister();
}

static int JsonGenericLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id, int dir)
{
    OutputJsonThreadCtx *thread = thread_data;
    EveJsonSimpleAppLayerLogger *al = SCEveJsonSimpleGetLogger(f->alproto);
    if (al == NULL) {
        return TM_ECODE_FAILED;
    }

    SCJsonBuilder *js = CreateEveHeader(p, dir, al->name, NULL, thread->ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!al->LogTx(tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(tv, p, p->flow, js, thread);
    SCJbFree(js);

    return TM_ECODE_OK;

error:
    SCJbFree(js);
    return TM_ECODE_FAILED;
}

static int JsonGenericDirPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    return JsonGenericLogger(tv, thread_data, p, f, state, tx, tx_id, LOG_DIR_PACKET);
}

static int JsonGenericDirFlowLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    return JsonGenericLogger(tv, thread_data, p, f, state, tx, tx_id, LOG_DIR_FLOW);
}

#define ARRAY_CAP_STEP 16
static EveJsonTxLoggerRegistrationData *preregistered_loggers = NULL;
static size_t preregistered_loggers_nb = 0;
static size_t preregistered_loggers_cap = 0;

// Plugins can preregister logger with this function :
// When an app-layer plugin is loaded, it wants to register its logger
// But the plugin is loaded before loggers can register
// The preregistration data will later be used by OutputRegisterLoggers
int SCOutputEvePreRegisterLogger(EveJsonTxLoggerRegistrationData reg_data)
{
    if (preregistered_loggers_nb == preregistered_loggers_cap) {
        void *tmp = SCRealloc(
                preregistered_loggers, sizeof(EveJsonTxLoggerRegistrationData) *
                                               (preregistered_loggers_cap + ARRAY_CAP_STEP));
        if (tmp == NULL) {
            return 1;
        }
        preregistered_loggers_cap += ARRAY_CAP_STEP;
        preregistered_loggers = tmp;
    }
    preregistered_loggers[preregistered_loggers_nb] = reg_data;
    preregistered_loggers_nb++;
    return 0;
}

static TxLogger JsonLoggerFromDir(uint8_t dir)
{
    if (dir == LOG_DIR_PACKET) {
        return JsonGenericDirPacketLogger;
    }
    BUG_ON(dir != LOG_DIR_FLOW);
    return JsonGenericDirFlowLogger;
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
    EveStreamLogRegister();
    /* json log */
    OutputJsonRegister();
    /* email logs */
    JsonSmtpLogRegister();
    /* http log */
    LogHttpLogRegister();
    JsonHttpLogRegister();
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_TX, "eve-log", "LogHttp2Log", "eve-log.http2",
            OutputJsonLogInitSub, ALPROTO_HTTP2, JsonGenericDirFlowLogger, HTTP2StateClosed,
            HTTP2StateClosed, JsonLogThreadInit, JsonLogThreadDeinit);
    /* tls log */
    LogTlsLogRegister();
    JsonTlsLogRegister();
    LogTlsStoreRegister();
    /* ssh */
    OutputRegisterTxSubModuleWithCondition(LOGGER_JSON_TX, "eve-log", "JsonSshLog", "eve-log.ssh",
            OutputJsonLogInitSub, ALPROTO_SSH, JsonGenericDirFlowLogger, SSHTxLogCondition,
            JsonLogThreadInit, JsonLogThreadDeinit);
    /* pcap log */
    PcapLogRegister();
    /* file log */
    JsonFileLogRegister();
    OutputFilestoreRegister();
    /* dns */
    JsonDnsLogRegister();
    /* mdns */
    JsonMdnsLogRegister();
    /* modbus */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonModbusLog", "eve-log.modbus",
            OutputJsonLogInitSub, ALPROTO_MODBUS, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);

    SCLogDebug("modbus json logger registered.");
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
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonTFTPLog", "eve-log.tftp",
            OutputJsonLogInitSub, ALPROTO_TFTP, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);

    SCLogDebug("TFTP JSON logger registered.");
    /* FTP and FTP-DATA JSON loggers. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonFTPLog", "eve-log.ftp",
            OutputJsonLogInitSub, ALPROTO_FTP, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonFTPLog", "eve-log.ftp",
            OutputJsonLogInitSub, ALPROTO_FTPDATA, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    SCLogDebug("FTP JSON logger registered.");

    /* SMB JSON logger. */
    JsonSMBLogRegister();
    /* IKE JSON logger. */
    JsonIKELogRegister();
    /* KRB5 JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonKRB5Log", "eve-log.krb5",
            OutputJsonLogInitSub, ALPROTO_KRB5, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);

    SCLogDebug("KRB5 JSON logger registered.");
    /* QUIC JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonQuicLog", "eve-log.quic",
            OutputJsonLogInitSub, ALPROTO_QUIC, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);

    SCLogDebug("quic json logger registered.");
    /* DHCP JSON logger. */
    JsonDHCPLogRegister();

    /* SIP JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonSIPLog", "eve-log.sip",
            OutputJsonLogInitSub, ALPROTO_SIP, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);

    SCLogDebug("SIP JSON logger registered.");
    /* RFB JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRFBLog", "eve-log.rfb",
            OutputJsonLogInitSub, ALPROTO_RFB, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* MQTT JSON logger. */
    JsonMQTTLogRegister();
    /* Pgsql JSON logger. */
    JsonPgsqlLogRegister();
    /* WebSocket JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonWebSocketLog", "eve-log.websocket",
            OutputJsonLogInitSub, ALPROTO_WEBSOCKET, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* Enip JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonEnipLog", "eve-log.enip",
            OutputJsonLogInitSub, ALPROTO_ENIP, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* Ldap JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonLdapLog", "eve-log.ldap",
            OutputJsonLogInitSub, ALPROTO_LDAP, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* DoH2 JSON logger. */
    JsonDoh2LogRegister();
    /* POP3 JSON logger */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonPop3Log", "eve-log.pop3",
            OutputJsonLogInitSub, ALPROTO_POP3, JsonGenericDirFlowLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* Mdns JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMdnsLog", "eve-log.template",
            OutputJsonLogInitSub, ALPROTO_MDNS, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* Template JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonTemplateLog", "eve-log.template",
            OutputJsonLogInitSub, ALPROTO_TEMPLATE, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    /* RDP JSON logger. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRdpLog", "eve-log.rdp",
            OutputJsonLogInitSub, ALPROTO_RDP, JsonGenericDirPacketLogger, JsonLogThreadInit,
            JsonLogThreadDeinit);
    SCLogDebug("rdp json logger registered.");
    /* DCERPC JSON logger. */
    JsonDCERPCLogRegister();
    /* app layer frames */
    JsonFrameLogRegister();
    /* BitTorrent DHT JSON logger */
    if (SCConfGetNode("app-layer.protocols.bittorrent-dht") != NULL) {
        /* Register as an eve sub-module. */
        OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonBitTorrentDHTLog",
                "eve-log.bittorrent-dht", OutputJsonLogInitSub, ALPROTO_BITTORRENT_DHT,
                JsonGenericDirPacketLogger, JsonLogThreadInit, JsonLogThreadDeinit);
    }
    /* ARP JSON logger */
    JsonArpLogRegister();

    for (size_t i = 0; i < preregistered_loggers_nb; i++) {
        OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", preregistered_loggers[i].logname,
                preregistered_loggers[i].confname, OutputJsonLogInitSub,
                preregistered_loggers[i].alproto, JsonLoggerFromDir(preregistered_loggers[i].dir),
                JsonLogThreadInit, JsonLogThreadDeinit);
        SCLogDebug(
                "%s JSON logger registered.", AppProtoToString(preregistered_loggers[i].alproto));
        RegisterSimpleJsonApplayerLogger(preregistered_loggers[i].alproto,
                (EveJsonSimpleTxLogFunc)preregistered_loggers[i].LogTx, NULL);
    }
}
