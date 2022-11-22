/* Copyright (C) 2007-2022 Open Information Security Foundation
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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  Pre-cooked threading runmodes.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "app-layer-parser.h"
#include "tm-threads.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-affinity.h"
#include "conf.h"
#include "queue.h"
#include "runmodes.h"
#include "runmode-af-packet.h"
#include "runmode-dpdk.h"
#include "runmode-erf-dag.h"
#include "runmode-erf-file.h"
#include "runmode-ipfw.h"
#include "runmode-napatech.h"
#include "runmode-netmap.h"
#include "runmode-nflog.h"
#include "runmode-nfq.h"
#include "runmode-pcap.h"
#include "runmode-pcap-file.h"
#include "runmode-pfring.h"
#include "runmode-unix-socket.h"
#include "runmode-windivert.h"
#include "util-unittest.h"
#include "util-misc.h"
#include "util-plugin.h"

#include "output.h"

#include "alert-fastlog.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "source-pfring.h"

#include "tmqh-flow.h"
#include "flow-manager.h"
#include "flow-bypass.h"
#include "counters.h"

#include "suricata-plugin.h"

int debuglog_enabled = 0;
int threading_set_cpu_affinity = FALSE;
uint64_t threading_set_stack_size = 0;

/* Runmode Global Thread Names */
const char *thread_name_autofp = "RX";
const char *thread_name_single = "W";
const char *thread_name_workers = "W";
const char *thread_name_verdict = "TX";
const char *thread_name_flow_mgr = "FM";
const char *thread_name_flow_rec = "FR";
const char *thread_name_flow_bypass = "FB";
const char *thread_name_unix_socket = "US";
const char *thread_name_detect_loader = "DL";
const char *thread_name_counter_stats = "CS";
const char *thread_name_counter_wakeup = "CW";

/**
 * \brief Holds description for a runmode.
 */
typedef struct RunMode_ {
    /* the runmode type */
    enum RunModes runmode;
    const char *name;
    const char *description;
    /* runmode function */
    int (*RunModeFunc)(void);
    void (*RunModeIsIPSEnabled)(void);
} RunMode;

typedef struct RunModes_ {
    int cnt;
    RunMode *runmodes;
} RunModes;

static RunModes runmodes[RUNMODE_USER_MAX];

static char *active_runmode;

/* free list for our outputs */
typedef struct OutputFreeList_ {
    OutputModule *output_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(OutputFreeList_) entries;
} OutputFreeList;
static TAILQ_HEAD(, OutputFreeList_) output_free_list =
    TAILQ_HEAD_INITIALIZER(output_free_list);

/**
 * \internal
 * \brief Translate a runmode mode to a printale string.
 *
 * \param runmode Runmode to be converted into a printable string.
 *
 * \retval string Printable string.
 */
static const char *RunModeTranslateModeToName(int runmode)
{
    switch (runmode) {
        case RUNMODE_PCAP_DEV:
            return "PCAP_DEV";
        case RUNMODE_PCAP_FILE:
            return "PCAP_FILE";
        case RUNMODE_PFRING:
#ifdef HAVE_PFRING
            return "PFRING";
#else
            return "PFRING(DISABLED)";
#endif
        case RUNMODE_PLUGIN:
            return "PLUGIN";
        case RUNMODE_NFQ:
            return "NFQ";
        case RUNMODE_NFLOG:
            return "NFLOG";
        case RUNMODE_IPFW:
            return "IPFW";
        case RUNMODE_ERF_FILE:
            return "ERF_FILE";
        case RUNMODE_DAG:
            return "ERF_DAG";
        case RUNMODE_NAPATECH:
            return "NAPATECH";
        case RUNMODE_UNITTEST:
            return "UNITTEST";
        case RUNMODE_AFP_DEV:
            return "AF_PACKET_DEV";
        case RUNMODE_NETMAP:
#ifdef HAVE_NETMAP
            return "NETMAP";
#else
            return "NETMAP(DISABLED)";
#endif
        case RUNMODE_UNIX_SOCKET:
            return "UNIX_SOCKET";
        case RUNMODE_WINDIVERT:
#ifdef WINDIVERT
            return "WINDIVERT";
#else
            return "WINDIVERT(DISABLED)";
#endif
        case RUNMODE_DPDK:
#ifdef HAVE_DPDK
            return "DPDK";
#else
            return "DPDK(DISABLED)";
#endif

        default:
            FatalError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
    }
}

/**
 * \internal
 * \brief Dispatcher function for runmodes.  Calls the required runmode function
 *        based on runmode + runmode_custom_id.
 *
 * \param runmode            The runmode type.
 * \param runmode_customd_id The runmode custom id.
 */
static RunMode *RunModeGetCustomMode(enum RunModes runmode, const char *custom_mode)
{
    if (runmode < RUNMODE_USER_MAX) {
        for (int i = 0; i < runmodes[runmode].cnt; i++) {
            if (strcmp(runmodes[runmode].runmodes[i].name, custom_mode) == 0)
                return &runmodes[runmode].runmodes[i];
        }
    }
    return NULL;
}


/**
 * Return the running mode
 *
 * The returned string must not be freed.
 *
 * \return a string containing the current running mode
 */
char *RunmodeGetActive(void)
{
    return active_runmode;
}

/**
 * Return the running mode
 *
 * The returned string must not be freed.
 *
 * \return a string containing the current running mode
 */
const char *RunModeGetMainMode(void)
{
    int mainmode = RunmodeGetCurrent();

    return RunModeTranslateModeToName(mainmode);
}

/**
 * \brief Register all runmodes in the engine.
 */
void RunModeRegisterRunModes(void)
{
    memset(runmodes, 0, sizeof(runmodes));

    RunModeIdsPcapRegister();
    RunModeFilePcapRegister();
    RunModeIdsPfringRegister();
    RunModeIpsNFQRegister();
    RunModeIpsIPFWRegister();
    RunModeErfFileRegister();
    RunModeErfDagRegister();
    RunModeNapatechRegister();
    RunModeIdsAFPRegister();
    RunModeIdsNetmapRegister();
    RunModeIdsNflogRegister();
    RunModeUnixSocketRegister();
    RunModeIpsWinDivertRegister();
    RunModeDpdkRegister();
#ifdef UNITTESTS
    UtRunModeRegister();
#endif
    return;
}

/**
 * \brief Lists all registered runmodes.
 */
void RunModeListRunmodes(void)
{
    printf("------------------------------------- Runmodes -------------------"
           "-----------------------\n");

    printf("| %-17s | %-17s | %-10s \n",
           "RunMode Type", "Custom Mode ", "Description");
    printf("|-----------------------------------------------------------------"
           "-----------------------\n");
    int i = RUNMODE_UNKNOWN + 1;
    int j = 0;
    for ( ; i < RUNMODE_USER_MAX; i++) {
        int mode_displayed = 0;
        for (j = 0; j < runmodes[i].cnt; j++) {
            if (mode_displayed == 1) {
                printf("|                   ----------------------------------------------"
                       "-----------------------\n");
                RunMode *runmode = &runmodes[i].runmodes[j];
                printf("| %-17s | %-17s | %-27s \n",
                       "",
                       runmode->name,
                       runmode->description);
            } else {
                RunMode *runmode = &runmodes[i].runmodes[j];
                printf("| %-17s | %-17s | %-27s \n",
                       RunModeTranslateModeToName(runmode->runmode),
                       runmode->name,
                       runmode->description);
            }
            if (mode_displayed == 0)
                mode_displayed = 1;
        }
        if (mode_displayed == 1) {
            printf("|-----------------------------------------------------------------"
                   "-----------------------\n");
        }
    }

    return;
}

static const char *RunModeGetConfOrDefault(int capture_mode, const char *capture_plugin_name)
{
    const char *custom_mode = NULL;
    const char *val = NULL;
    if (ConfGet("runmode", &val) != 1) {
        custom_mode = NULL;
    } else {
        custom_mode = val;
    }

    if ((custom_mode == NULL) || (strcmp(custom_mode, "auto") == 0)) {
        switch (capture_mode) {
            case RUNMODE_PCAP_DEV:
                custom_mode = RunModeIdsGetDefaultMode();
                break;
            case RUNMODE_PCAP_FILE:
                custom_mode = RunModeFilePcapGetDefaultMode();
                break;
#ifdef HAVE_PFRING
            case RUNMODE_PFRING:
                custom_mode = RunModeIdsPfringGetDefaultMode();
                break;
#endif
            case RUNMODE_PLUGIN: {
#ifdef HAVE_PLUGINS
                SCCapturePlugin *plugin = SCPluginFindCaptureByName(capture_plugin_name);
                if (plugin == NULL) {
                    FatalError(SC_ERR_PLUGIN, "No capture plugin found with name %s",
                            capture_plugin_name);
                }
                custom_mode = (const char *)plugin->GetDefaultMode();
#endif
                break;
            }
            case RUNMODE_NFQ:
                custom_mode = RunModeIpsNFQGetDefaultMode();
                break;
            case RUNMODE_IPFW:
                custom_mode = RunModeIpsIPFWGetDefaultMode();
                break;
            case RUNMODE_ERF_FILE:
                custom_mode = RunModeErfFileGetDefaultMode();
                break;
            case RUNMODE_DAG:
                custom_mode = RunModeErfDagGetDefaultMode();
                break;
            case RUNMODE_NAPATECH:
                custom_mode = RunModeNapatechGetDefaultMode();
                break;
            case RUNMODE_AFP_DEV:
                custom_mode = RunModeAFPGetDefaultMode();
                break;
            case RUNMODE_NETMAP:
                custom_mode = RunModeNetmapGetDefaultMode();
                break;
            case RUNMODE_UNIX_SOCKET:
                custom_mode = RunModeUnixSocketGetDefaultMode();
                break;
            case RUNMODE_NFLOG:
                custom_mode = RunModeIdsNflogGetDefaultMode();
                break;
#ifdef WINDIVERT
            case RUNMODE_WINDIVERT:
                custom_mode = RunModeIpsWinDivertGetDefaultMode();
                break;
#endif
#ifdef HAVE_DPDK
            case RUNMODE_DPDK:
                custom_mode = RunModeDpdkGetDefaultMode();
                break;
#endif
            default:
                custom_mode = NULL;
                break;
        }
    } else {
        /* Add compability with old 'worker' name */
        if (!strcmp("worker", custom_mode)) {
            char *local_custom_mode = NULL;
            SCLogWarning(SC_ERR_RUNMODE, "'worker' mode have been renamed "
                                         "to 'workers', please modify your setup.");
            local_custom_mode = SCStrdup("workers");
            if (unlikely(local_custom_mode == NULL)) {
                SCLogWarning(SC_ERR_FATAL, "Unable to dup custom mode");
            }
            custom_mode = local_custom_mode;
        }
    }

    return custom_mode;
}

void RunModeEngineIsIPS(int capture_mode, const char *runmode, const char *capture_plugin_name)
{
    if (runmode == NULL) {
        runmode = RunModeGetConfOrDefault(capture_mode, capture_plugin_name);
    }

    RunMode *mode = RunModeGetCustomMode(capture_mode, runmode);
    if (mode == NULL) {
        return;
    }

    if (mode->RunModeIsIPSEnabled != NULL) {
        mode->RunModeIsIPSEnabled();
    }
}

/**
 */
void RunModeDispatch(int runmode, const char *custom_mode, const char *capture_plugin_name,
        const char *capture_plugin_args)
{
    char *local_custom_mode = NULL;

    if (custom_mode == NULL) {
        custom_mode = RunModeGetConfOrDefault(runmode, capture_plugin_name);
        if (custom_mode == NULL)
            FatalError(SC_ERR_FATAL, "Unknown runtime mode. Aborting");
    }

    RunMode *mode = RunModeGetCustomMode(runmode, custom_mode);
    if (mode == NULL) {
        SCLogError(SC_ERR_RUNMODE, "The custom type \"%s\" doesn't exist "
                   "for this runmode type \"%s\".  Please use --list-runmodes to "
                   "see available custom types for this runmode",
                   custom_mode, RunModeTranslateModeToName(runmode));
        exit(EXIT_FAILURE);
    }

    /* Export the custom mode */
    if (active_runmode) {
        SCFree(active_runmode);
    }
    active_runmode = SCStrdup(custom_mode);
    if (unlikely(active_runmode == NULL)) {
        FatalError(SC_ERR_FATAL, "Unable to dup active mode");
    }

    if (strcasecmp(active_runmode, "autofp") == 0) {
        TmqhFlowPrintAutofpHandler();
    }

    mode->RunModeFunc();

    if (local_custom_mode != NULL)
        SCFree(local_custom_mode);

    /* Check if the alloted queues have at least 1 reader and writer */
    TmValidateQueueState();

    if (runmode != RUNMODE_UNIX_SOCKET) {
        /* spawn management threads */
        FlowManagerThreadSpawn();
        FlowRecyclerThreadSpawn();
        if (RunModeNeedsBypassManager()) {
            BypassedFlowManagerThreadSpawn();
        }
        StatsSpawnThreads();
    }
}

static int g_runmode_needs_bypass = 0;

void RunModeEnablesBypassManager(void)
{
    g_runmode_needs_bypass = 1;
}

int RunModeNeedsBypassManager(void)
{
    return g_runmode_needs_bypass;
}



/**
 * \brief Registers a new runmode.
 *
 * \param runmode     Runmode type.
 * \param name        Custom mode for this specific runmode type.  Within each
 *                    runmode type, each custom name is a primary key.
 * \param description Description for this runmode.
 * \param RunModeFunc The function to be run for this runmode.
 */
void RunModeRegisterNewRunMode(enum RunModes runmode, const char *name, const char *description,
        int (*RunModeFunc)(void), void (*RunModeIsIPSEnabled)(void))
{
    if (RunModeGetCustomMode(runmode, name) != NULL) {
        FatalError(SC_ERR_RUNMODE, "runmode '%s' has already "
                   "been registered. Please use an unique name.", name);
    }

    void *ptmp = SCRealloc(runmodes[runmode].runmodes,
                     (runmodes[runmode].cnt + 1) * sizeof(RunMode));
    if (ptmp == NULL) {
        SCFree(runmodes[runmode].runmodes);
        runmodes[runmode].runmodes = NULL;
        exit(EXIT_FAILURE);
    }
    runmodes[runmode].runmodes = ptmp;

    RunMode *mode = &runmodes[runmode].runmodes[runmodes[runmode].cnt];
    runmodes[runmode].cnt++;
    memset(mode, 0x00, sizeof(*mode));

    mode->runmode = runmode;
    mode->name = SCStrdup(name);
    if (unlikely(mode->name == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->description = SCStrdup(description);
    if (unlikely(mode->description == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
    }
    mode->RunModeFunc = RunModeFunc;
    mode->RunModeIsIPSEnabled = RunModeIsIPSEnabled;

    return;
}

/**
 * Setup the outputs for this run mode.
 *
 * \param tv The ThreadVars for the thread the outputs will be
 * appended to.
 */
static void RunOutputFreeList(void)
{
    OutputFreeList *output;
    while ((output = TAILQ_FIRST(&output_free_list))) {
        SCLogDebug("output %s %p %p", output->output_module->name, output,
            output->output_ctx);

        if (output->output_ctx != NULL && output->output_ctx->DeInit != NULL)
            output->output_ctx->DeInit(output->output_ctx);

        TAILQ_REMOVE(&output_free_list, output, entries);
        SCFree(output);
    }
}

static int file_logger_count = 0;
static int filedata_logger_count = 0;
static LoggerId logger_bits[ALPROTO_MAX];

int RunModeOutputFileEnabled(void)
{
    return file_logger_count > 0;
}

int RunModeOutputFiledataEnabled(void)
{
    return filedata_logger_count > 0;
}

bool IsRunModeSystem(enum RunModes run_mode_to_check)
{
    switch (run_mode_to_check) {
        case RUNMODE_PCAP_FILE:
        case RUNMODE_ERF_FILE:
        case RUNMODE_ENGINE_ANALYSIS:
            return false;
            break;
        default:
            return true;
    }
}

bool IsRunModeOffline(enum RunModes run_mode_to_check)
{
    switch(run_mode_to_check) {
        case RUNMODE_CONF_TEST:
        case RUNMODE_PCAP_FILE:
        case RUNMODE_ERF_FILE:
        case RUNMODE_ENGINE_ANALYSIS:
        case RUNMODE_UNIX_SOCKET:
            return true;
            break;
        default:
            return false;
    }
}

/**
 * Cleanup the run mode.
 */
void RunModeShutDown(void)
{
    RunOutputFreeList();

    OutputPacketShutdown();
    OutputTxShutdown();
    OutputFileShutdown();
    OutputFiledataShutdown();
    OutputStreamingShutdown();
    OutputStatsShutdown();
    OutputFlowShutdown();

    OutputClearActiveLoggers();

    /* Reset logger counts. */
    file_logger_count = 0;
    filedata_logger_count = 0;
}

/** \internal
 *  \brief add Sub RunModeOutput to list for Submodule so we can free
 *         the output ctx at shutdown and unix socket reload */
static void AddOutputToFreeList(OutputModule *module, OutputCtx *output_ctx)
{
    OutputFreeList *fl_output = SCCalloc(1, sizeof(OutputFreeList));
    if (unlikely(fl_output == NULL))
        return;
    fl_output->output_module = module;
    fl_output->output_ctx = output_ctx;
    TAILQ_INSERT_TAIL(&output_free_list, fl_output, entries);
}

/** \brief Turn output into thread module */
static void SetupOutput(const char *name, OutputModule *module, OutputCtx *output_ctx)
{
    /* flow logger doesn't run in the packet path */
    if (module->FlowLogFunc) {
        OutputRegisterFlowLogger(module->name, module->FlowLogFunc,
            output_ctx, module->ThreadInit, module->ThreadDeinit,
            module->ThreadExitPrintStats);
        return;
    }
    /* stats logger doesn't run in the packet path */
    if (module->StatsLogFunc) {
        OutputRegisterStatsLogger(module->name, module->StatsLogFunc,
            output_ctx,module->ThreadInit, module->ThreadDeinit,
            module->ThreadExitPrintStats);
        return;
    }

    if (module->logger_id == LOGGER_ALERT_DEBUG) {
        debuglog_enabled = 1;
    }

    if (module->PacketLogFunc) {
        SCLogDebug("%s is a packet logger", module->name);
        OutputRegisterPacketLogger(module->logger_id, module->name,
            module->PacketLogFunc, module->PacketConditionFunc, output_ctx,
            module->ThreadInit, module->ThreadDeinit,
            module->ThreadExitPrintStats);
    } else if (module->TxLogFunc) {
        SCLogDebug("%s is a tx logger", module->name);
        OutputRegisterTxLogger(module->logger_id, module->name, module->alproto,
                module->TxLogFunc, output_ctx, module->tc_log_progress,
                module->ts_log_progress, module->TxLogCondition,
                module->ThreadInit, module->ThreadDeinit,
                module->ThreadExitPrintStats);
        /* Not used with wild card loggers */
        if (module->alproto != ALPROTO_UNKNOWN) {
            logger_bits[module->alproto] |= BIT_U32(module->logger_id);
        }
    } else if (module->FiledataLogFunc) {
        SCLogDebug("%s is a filedata logger", module->name);
        OutputRegisterFiledataLogger(module->logger_id, module->name,
            module->FiledataLogFunc, output_ctx, module->ThreadInit,
            module->ThreadDeinit, module->ThreadExitPrintStats);
        filedata_logger_count++;
    } else if (module->FileLogFunc) {
        SCLogDebug("%s is a file logger", module->name);
        OutputRegisterFileLogger(module->logger_id, module->name,
            module->FileLogFunc, output_ctx, module->ThreadInit,
            module->ThreadDeinit, module->ThreadExitPrintStats);
        file_logger_count++;
    } else if (module->StreamingLogFunc) {
        SCLogDebug("%s is a streaming logger", module->name);
        OutputRegisterStreamingLogger(module->logger_id, module->name,
            module->StreamingLogFunc, output_ctx, module->stream_type,
            module->ThreadInit, module->ThreadDeinit,
            module->ThreadExitPrintStats);
    } else {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Unknown logger type: name=%s",
            module->name);
    }
}

static void RunModeInitializeEveOutput(ConfNode *conf, OutputCtx *parent_ctx)
{
    ConfNode *types = ConfNodeLookupChild(conf, "types");
    SCLogDebug("types %p", types);
    if (types == NULL) {
        return;
    }

    ConfNode *type = NULL;
    TAILQ_FOREACH(type, &types->head, next) {
        int sub_count = 0;
        char subname[256];

        if (strcmp(type->val, "ikev2") == 0) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT, "eve module 'ikev2' has been replaced by 'ike'");
            strlcpy(subname, "eve-log.ike", sizeof(subname));
        } else {
            snprintf(subname, sizeof(subname), "eve-log.%s", type->val);
        }

        SCLogConfig("enabling 'eve-log' module '%s'", type->val);

        ConfNode *sub_output_config = ConfNodeLookupChild(type, type->val);
        if (sub_output_config != NULL) {
            const char *enabled = ConfNodeLookupChildValue(
                sub_output_config, "enabled");
            if (enabled != NULL && !ConfValIsTrue(enabled)) {
                continue;
            }
        }

        /* Now setup all registers logger of this name. */
        OutputModule *sub_module;
        TAILQ_FOREACH(sub_module, &output_modules, entries) {
            if (strcmp(subname, sub_module->conf_name) == 0) {
                sub_count++;

                if (sub_module->parent_name == NULL ||
                        strcmp(sub_module->parent_name, "eve-log") != 0) {
                    FatalError(SC_ERR_INVALID_ARGUMENT,
                            "bad parent for %s", subname);
                }
                if (sub_module->InitSubFunc == NULL) {
                    FatalError(SC_ERR_INVALID_ARGUMENT,
                            "bad sub-module for %s", subname);
                }

                /* pass on parent output_ctx */
                OutputInitResult result =
                    sub_module->InitSubFunc(sub_output_config, parent_ctx);
                if (!result.ok || result.ctx == NULL) {
                    continue;
                }

                AddOutputToFreeList(sub_module, result.ctx);
                SetupOutput(sub_module->name, sub_module,
                        result.ctx);
            }
        }

        /* Error is no registered loggers with this name
         * were found .*/
        if (!sub_count) {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                    "No output module named %s", subname);
            continue;
        }
    }
}

static void RunModeInitializeLuaOutput(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputModule *lua_module = OutputGetModuleByConfName("lua");
    BUG_ON(lua_module == NULL);

    ConfNode *scripts = ConfNodeLookupChild(conf, "scripts");
    BUG_ON(scripts == NULL); //TODO

    OutputModule *m;
    TAILQ_FOREACH(m, &parent_ctx->submodules, entries) {
        SCLogDebug("m %p %s:%s", m, m->name, m->conf_name);

        ConfNode *script = NULL;
        TAILQ_FOREACH(script, &scripts->head, next) {
            SCLogDebug("script %s", script->val);
            if (strcmp(script->val, m->conf_name) == 0) {
                break;
            }
        }
        BUG_ON(script == NULL);

        /* pass on parent output_ctx */
        OutputInitResult result = m->InitSubFunc(script, parent_ctx);
        if (!result.ok || result.ctx == NULL) {
            continue;
        }

        AddOutputToFreeList(m, result.ctx);
        SetupOutput(m->name, m, result.ctx);
    }
}

extern bool g_file_logger_enabled;
extern bool g_filedata_logger_enabled;

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
    const char *enabled;
    char tls_log_enabled = 0;
    char tls_store_present = 0;

    memset(&logger_bits, 0, sizeof(logger_bits));

    TAILQ_FOREACH(output, &outputs->head, next) {

        output_config = ConfNodeLookupChild(output, output->val);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            FatalError(SC_ERR_INVALID_ARGUMENT,
                "Failed to lookup configuration child node: %s", output->val);
        }

        if (strcmp(output->val, "tls-store") == 0) {
            tls_store_present = 1;
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled == NULL || !ConfValIsTrue(enabled)) {
            continue;
        }

        if (strcmp(output->val, "file-log") == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED, "file-log is no longer supported,"
                                               " use eve.files instead "
                                               "(see ticket #2376"
                                               " for an explanation)");
            continue;
        } else if (strncmp(output->val, "unified-", sizeof("unified-") - 1) == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED, "Unified1 is no longer supported,"
                                               " use Unified2 instead "
                                               "(see ticket #353"
                                               " for an explanation)");
            continue;
        } else if (strncmp(output->val, "unified2-", sizeof("unified2-") - 1) == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "Unified2 is no longer supported.");
            continue;
        } else if (strcmp(output->val, "lua") == 0) {
#ifndef HAVE_LUA
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "lua support not compiled in. Reconfigure/"
                    "recompile with lua(jit) and its development "
                    "files installed to add lua support.");
            continue;
#endif
        } else if (strcmp(output->val, "dns-log") == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "dns-log is not longer available as of Suricata 5.0");
            continue;
        } else if (strcmp(output->val, "tls-log") == 0) {
            tls_log_enabled = 1;
        }

        OutputModule *module;
        int count = 0;
        TAILQ_FOREACH(module, &output_modules, entries) {
            if (strcmp(module->conf_name, output->val) != 0) {
                continue;
            }

            count++;

            OutputCtx *output_ctx = NULL;
            if (module->InitFunc != NULL) {
                OutputInitResult r = module->InitFunc(output_config);
                if (!r.ok) {
                    FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                        "output module \"%s\": setup failed", output->val);
                    continue;
                } else if (r.ctx == NULL) {
                    continue;
                }
                output_ctx = r.ctx;
            } else if (module->InitSubFunc != NULL) {
                SCLogInfo("skipping submodule");
                continue;
            }

            // TODO if module == parent, find it's children
            if (strcmp(output->val, "eve-log") == 0) {
                RunModeInitializeEveOutput(output_config, output_ctx);

                /* add 'eve-log' to free list as it's the owner of the
                 * main output ctx from which the sub-modules share the
                 * LogFileCtx */
                AddOutputToFreeList(module, output_ctx);
            } else if (strcmp(output->val, "lua") == 0) {
                SCLogDebug("handle lua");
                if (output_ctx == NULL)
                    continue;
                RunModeInitializeLuaOutput(output_config, output_ctx);
                AddOutputToFreeList(module, output_ctx);
            } else {
                AddOutputToFreeList(module, output_ctx);
                SetupOutput(module->name, module, output_ctx);
            }
        }
        if (count == 0) {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                "No output module named %s", output->val);
            continue;
        }
    }

    /* Backward compatibility code */
    if (!tls_store_present && tls_log_enabled) {
        /* old YAML with no "tls-store" in outputs. "tls-log" value needs
         * to be started using 'tls-log' config as own config */
        SCLogWarning(SC_ERR_CONF_YAML_ERROR,
                     "Please use 'tls-store' in YAML to configure TLS storage");

        TAILQ_FOREACH(output, &outputs->head, next) {
            output_config = ConfNodeLookupChild(output, output->val);

            if (strcmp(output->val, "tls-log") == 0) {

                OutputModule *module = OutputGetModuleByConfName("tls-store");
                if (module == NULL) {
                    SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                            "No output module named %s, ignoring", "tls-store");
                    continue;
                }

                OutputCtx *output_ctx = NULL;
                if (module->InitFunc != NULL) {
                    OutputInitResult r = module->InitFunc(output_config);
                    if (!r.ok) {
                        FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                                "output module setup failed");
                        continue;
                    } else if (r.ctx == NULL) {
                        continue;
                    }
                    output_ctx = r.ctx;
                }

                AddOutputToFreeList(module, output_ctx);
                SetupOutput(module->name, module, output_ctx);
            }
        }
    }

    /* register the logger bits to the app-layer */
    AppProto a;
    for (a = 0; a < ALPROTO_MAX; a++) {
        if (AppLayerParserSupportsFiles(IPPROTO_TCP, a)) {
            if (g_file_logger_enabled)
                logger_bits[a] |= BIT_U32(LOGGER_FILE);
            if (g_filedata_logger_enabled)
                logger_bits[a] |= BIT_U32(LOGGER_FILEDATA);
            SCLogDebug("IPPROTO_TCP::%s: g_file_logger_enabled %d g_filedata_logger_enabled %d -> "
                       "%08x",
                    AppProtoToString(a), g_file_logger_enabled, g_filedata_logger_enabled,
                    logger_bits[a]);
        }
        if (AppLayerParserSupportsFiles(IPPROTO_UDP, a)) {
            if (g_file_logger_enabled)
                logger_bits[a] |= BIT_U32(LOGGER_FILE);
            if (g_filedata_logger_enabled)
                logger_bits[a] |= BIT_U32(LOGGER_FILEDATA);
        }

        if (logger_bits[a] == 0)
            continue;

        const int tcp = AppLayerParserProtocolHasLogger(IPPROTO_TCP, a) | (g_file_logger_enabled) |
                        (g_filedata_logger_enabled);
        const int udp = AppLayerParserProtocolHasLogger(IPPROTO_UDP, a) | (g_file_logger_enabled) |
                        (g_filedata_logger_enabled);
        SCLogDebug("tcp %d udp %d", tcp, udp);

        SCLogDebug("logger for %s: %s %s", AppProtoToString(a),
                tcp ? "true" : "false", udp ? "true" : "false");

        SCLogDebug("logger bits for %s: %08x", AppProtoToString(a), logger_bits[a]);
        if (tcp)
            AppLayerParserRegisterLoggerBits(IPPROTO_TCP, a, logger_bits[a]);
        if (udp)
            AppLayerParserRegisterLoggerBits(IPPROTO_UDP, a, logger_bits[a]);

    }
    OutputSetupActiveLoggers();
}

float threading_detect_ratio = 1;

/**
 * Initialize multithreading settings.
 */
void RunModeInitialize(void)
{
    threading_set_cpu_affinity = FALSE;
    if ((ConfGetBool("threading.set-cpu-affinity", &threading_set_cpu_affinity)) == 0) {
        threading_set_cpu_affinity = FALSE;
    }
    /* try to get custom cpu mask value if needed */
    if (threading_set_cpu_affinity == TRUE) {
        AffinitySetupLoadFromConfig();
    }
    if ((ConfGetFloat("threading.detect-thread-ratio", &threading_detect_ratio)) != 1) {
        if (ConfGetNode("threading.detect-thread-ratio") != NULL)
            WarnInvalidConfEntry("threading.detect-thread-ratio", "%s", "1");
        threading_detect_ratio = 1;
    }

    SCLogDebug("threading.detect-thread-ratio %f", threading_detect_ratio);

    /*
     * Check if there's a configuration setting for the per-thread stack size
     * in case the default per-thread stack size is to be adjusted
     */
    const char *ss = NULL;
    if ((ConfGet("threading.stack-size", &ss)) == 1) {
        if (ss != NULL) {
            if (ParseSizeStringU64(ss, &threading_set_stack_size) < 0) {
                FatalError(SC_ERR_INVALID_ARGUMENT,
                        "Failed to initialize thread_stack_size output, invalid limit: %s", ss);
            }
        }
    }

    SCLogDebug("threading.stack-size %" PRIu64, threading_set_stack_size);
}
