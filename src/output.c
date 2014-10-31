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
 *
 * Output registration functions
 */

#include "suricata-common.h"
#include "flow.h"
#include "conf.h"
#include "tm-threads.h"
#include "util-error.h"
#include "util-debug.h"
#include "output.h"

static TAILQ_HEAD(, OutputModule_) output_modules =
    TAILQ_HEAD_INITIALIZER(output_modules);

/**
 * Registry of flags to be updated on file rotation notification.
 */
typedef struct OutputFileRolloverFlag_ {
    int *flag;

    TAILQ_ENTRY(OutputFileRolloverFlag_) entries;
} OutputFileRolloverFlag;

TAILQ_HEAD(, OutputFileRolloverFlag_) output_file_rotation_flags =
    TAILQ_HEAD_INITIALIZER(output_file_rotation_flags);

/**
 * \brief Register an output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *))
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
    SCLogError(SC_ERR_FATAL, "Fatal error encountered in OutputRegisterModule. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a packet output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterPacketModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *),
    PacketLogger PacketLogFunc, PacketLogCondition PacketConditionFunc)
{
    if (unlikely(PacketLogFunc == NULL || PacketConditionFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->PacketLogFunc = PacketLogFunc;
    module->PacketConditionFunc = PacketConditionFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a packet output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterPacketSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *parent_ctx),
    PacketLogger PacketLogFunc, PacketLogCondition PacketConditionFunc)
{
    if (unlikely(PacketLogFunc == NULL || PacketConditionFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->PacketLogFunc = PacketLogFunc;
    module->PacketConditionFunc = PacketConditionFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Packet logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a tx output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterTxModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), AppProto alproto,
    TxLogger TxLogFunc)
{
    if (unlikely(TxLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->TxLogFunc = TxLogFunc;
    module->alproto = alproto;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

void
OutputRegisterTxSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *parent_ctx),
    AppProto alproto, TxLogger TxLogFunc)
{
    if (unlikely(TxLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->TxLogFunc = TxLogFunc;
    module->alproto = alproto;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Tx logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a file output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFileModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FileLogger FileLogFunc)
{
    if (unlikely(FileLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->FileLogFunc = FileLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("File logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a file output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFileSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FileLogger FileLogFunc)
{
    if (unlikely(FileLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FileLogFunc = FileLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("File logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a file data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFiledataModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FiledataLogger FiledataLogFunc)
{
    if (unlikely(FiledataLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->FiledataLogFunc = FiledataLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Filedata logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a file data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFiledataSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FiledataLogger FiledataLogFunc)
{
    if (unlikely(FiledataLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FiledataLogFunc = FiledataLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Filedata logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a flow output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFlowModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FlowLogger FlowLogFunc)
{
    if (unlikely(FlowLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->FlowLogFunc = FlowLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Flow logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a flow output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterFlowSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    FlowLogger FlowLogFunc)
{
    if (unlikely(FlowLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->FlowLogFunc = FlowLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Flow logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a streaming data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterStreamingModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), StreamingLogger StreamingLogFunc,
    enum OutputStreamingType stream_type)
{
    if (unlikely(StreamingLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->StreamingLogFunc = StreamingLogFunc;
    module->stream_type = stream_type;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Streaming logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a streaming data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterStreamingSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    StreamingLogger StreamingLogFunc, enum OutputStreamingType stream_type)
{
    if (unlikely(StreamingLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->StreamingLogFunc = StreamingLogFunc;
    module->stream_type = stream_type;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Streaming logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a stats data output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterStatsModule(const char *name, const char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), StatsLogger StatsLogFunc)
{
    if (unlikely(StatsLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->InitFunc = InitFunc;
    module->StatsLogFunc = StatsLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Register a stats data output sub-module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterStatsSubModule(const char *parent_name, const char *name,
    const char *conf_name, OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    StatsLogger StatsLogFunc)
{
    if (unlikely(StatsLogFunc == NULL)) {
        goto error;
    }

    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        goto error;
    }

    module->name = name;
    module->conf_name = conf_name;
    module->parent_name = parent_name;
    module->InitSubFunc = InitFunc;
    module->StatsLogFunc = StatsLogFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Stats logger \"%s\" registered.", name);
    return;
error:
    SCLogError(SC_ERR_FATAL, "Fatal error encountered. Exiting...");
    exit(EXIT_FAILURE);
}

/**
 * \brief Get an output module by name.
 *
 * \retval The OutputModule with the given name or NULL if no output module
 * with the given name is registered.
 */
OutputModule *
OutputGetModuleByConfName(const char *conf_name)
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
void
OutputDeregisterAll(void)
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

static int tls_loggers = 0;

int OutputTlsLoggerEnable(void)
{
    if (tls_loggers)
        return -1;
    tls_loggers++;
    return 0;
}

void OutputTlsLoggerDisable(void)
{
    if (tls_loggers)
        tls_loggers--;
}

static int ssh_loggers = 0;

int OutputSshLoggerEnable(void)
{
    if (ssh_loggers)
        return -1;
    ssh_loggers++;
    return 0;
}

void OutputSshLoggerDisable(void)
{
    if (ssh_loggers)
        ssh_loggers--;
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
