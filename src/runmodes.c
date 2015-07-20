/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#include "tm-threads.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-byte.h"
#include "util-affinity.h"
#include "conf.h"
#include "queue.h"
#include "runmodes.h"
#include "util-unittest.h"
#include "util-misc.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "output.h"

#include "source-pfring.h"

int debuglog_enabled = 0;

/**
 * \brief Holds description for a runmode.
 */
typedef struct RunMode_ {
    /* the runmode type */
    int runmode;
    const char *name;
    const char *description;
    /* runmode function */
    int (*RunModeFunc)(void);
} RunMode;

typedef struct RunModes_ {
    int no_of_runmodes;
    RunMode *runmodes;
} RunModes;

/**
 * A list of output modules that will be active for the run mode.
 */
typedef struct RunModeOutput_ {
    const char *name;
    TmModule *tm_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(RunModeOutput_) entries;
} RunModeOutput;
TAILQ_HEAD(, RunModeOutput_) RunModeOutputs =
    TAILQ_HEAD_INITIALIZER(RunModeOutputs);

static RunModes runmodes[RUNMODE_USER_MAX];

static char *active_runmode;

/* free list for our outputs */
typedef struct OutputFreeList_ {
    TmModule *tm_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(OutputFreeList_) entries;
} OutputFreeList;
TAILQ_HEAD(, OutputFreeList_) output_free_list =
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
        case RUNMODE_TILERA_MPIPE:
            return "MPIPE";
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
        default:
            SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
            exit(EXIT_FAILURE);
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
static RunMode *RunModeGetCustomMode(int runmode, const char *custom_mode)
{
    int i;

    for (i = 0; i < runmodes[runmode].no_of_runmodes; i++) {
        if (strcmp(runmodes[runmode].runmodes[i].name, custom_mode) == 0)
            return &runmodes[runmode].runmodes[i];
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
    RunModeTileMpipeRegister();
    RunModeUnixSocketRegister();
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
        for (j = 0; j < runmodes[i].no_of_runmodes; j++) {
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

/**
 */
void RunModeDispatch(int runmode, const char *custom_mode)
{
    char *local_custom_mode = NULL;

    if (custom_mode == NULL) {
        char *val = NULL;
        if (ConfGet("runmode", &val) != 1) {
            custom_mode = NULL;
        } else {
            custom_mode = val;
        }
    }

    if (custom_mode == NULL || strcmp(custom_mode, "auto") == 0) {
        switch (runmode) {
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
            case RUNMODE_TILERA_MPIPE:
                custom_mode = RunModeTileMpipeGetDefaultMode();
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
            default:
                SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
                exit(EXIT_FAILURE);
        }
    } else { /* if (custom_mode == NULL) */
        /* Add compability with old 'worker' name */
        if (!strcmp("worker", custom_mode)) {
            SCLogWarning(SC_ERR_RUNMODE, "'worker' mode have been renamed "
                         "to 'workers', please modify your setup.");
            local_custom_mode = SCStrdup("workers");
            if (unlikely(local_custom_mode == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup custom mode");
                exit(EXIT_FAILURE);
            }
            custom_mode = local_custom_mode;
        }
    }

#ifdef __SC_CUDA_SUPPORT__
    if (PatternMatchDefaultMatcher() == MPM_AC_CUDA &&
        strcasecmp(custom_mode, "autofp") != 0) {
        SCLogError(SC_ERR_RUNMODE, "When using a cuda mpm, the only runmode we "
                   "support is autofp.");
        exit(EXIT_FAILURE);
    }
#endif

    RunMode *mode = RunModeGetCustomMode(runmode, custom_mode);
    if (mode == NULL) {
        SCLogError(SC_ERR_RUNMODE, "The custom type \"%s\" doesn't exist "
                   "for this runmode type \"%s\".  Please use --list-runmodes to "
                   "see available custom types for this runmode",
                   custom_mode, RunModeTranslateModeToName(runmode));
        exit(EXIT_FAILURE);
    }

    /* Export the custom mode */
    active_runmode = SCStrdup(custom_mode);
    if (unlikely(active_runmode == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup active mode");
        exit(EXIT_FAILURE);
    }

    mode->RunModeFunc();

    if (local_custom_mode != NULL)
        SCFree(local_custom_mode);
    return;
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
void RunModeRegisterNewRunMode(int runmode, const char *name,
                               const char *description,
                               int (*RunModeFunc)(void))
{
    void *ptmp;
    if (RunModeGetCustomMode(runmode, name) != NULL) {
        SCLogError(SC_ERR_RUNMODE, "A runmode by this custom name has already "
                   "been registered.  Please use an unique name");
        return;
    }

    ptmp = SCRealloc(runmodes[runmode].runmodes,
                     (runmodes[runmode].no_of_runmodes + 1) * sizeof(RunMode));
    if (ptmp == NULL) {
        SCFree(runmodes[runmode].runmodes);
        runmodes[runmode].runmodes = NULL;
        exit(EXIT_FAILURE);
    }
    runmodes[runmode].runmodes = ptmp;

    RunMode *mode = &runmodes[runmode].runmodes[runmodes[runmode].no_of_runmodes];
    runmodes[runmode].no_of_runmodes++;

    mode->runmode = runmode;
    mode->name = SCStrdup(name);
    if (unlikely(mode->name == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
        exit(EXIT_FAILURE);
    }
    mode->description = SCStrdup(description);
    if (unlikely(mode->description == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate string");
        exit(EXIT_FAILURE);
    }
    mode->RunModeFunc = RunModeFunc;

    return;
}

/**
 * Setup the outputs for this run mode.
 *
 * \param tv The ThreadVars for the thread the outputs will be
 * appended to.
 */
void RunOutputFreeList(void)
{
    OutputFreeList *output;
    while ((output = TAILQ_FIRST(&output_free_list))) {
        SCLogDebug("output %s %p %p", output->tm_module->name, output, output->output_ctx);

        if (output->output_ctx != NULL && output->output_ctx->DeInit != NULL)
            output->output_ctx->DeInit(output->output_ctx);

        TAILQ_REMOVE(&output_free_list, output, entries);
        SCFree(output);
    }
}

static TmModule *pkt_logger_module = NULL;
static TmModule *tx_logger_module = NULL;
static TmModule *file_logger_module = NULL;
static TmModule *filedata_logger_module = NULL;
static TmModule *streaming_logger_module = NULL;

int RunModeOutputFileEnabled(void)
{
    return (file_logger_module != NULL);
}

int RunModeOutputFiledataEnabled(void)
{
    return (filedata_logger_module != NULL);
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

    /* Close any log files. */
    RunModeOutput *output;
    while ((output = TAILQ_FIRST(&RunModeOutputs))) {
        SCLogDebug("Shutting down output %s.", output->tm_module->name);
        TAILQ_REMOVE(&RunModeOutputs, output, entries);
        SCFree(output);
    }

    /* reset logger pointers */
    pkt_logger_module = NULL;
    tx_logger_module = NULL;
    file_logger_module = NULL;
    filedata_logger_module = NULL;
    streaming_logger_module = NULL;
}

/** \internal
 *  \brief add Sub RunModeOutput to list for Submodule so we can free
 *         the output ctx at shutdown and unix socket reload */
static void AddOutputToFreeList(OutputModule *module, OutputCtx *output_ctx)
{
    TmModule *tm_module = TmModuleGetByName(module->name);
    if (tm_module == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                "TmModuleGetByName for %s failed", module->name);
        exit(EXIT_FAILURE);
    }
    OutputFreeList *fl_output = SCCalloc(1, sizeof(OutputFreeList));
    if (unlikely(fl_output == NULL))
        return;
    fl_output->tm_module = tm_module;
    fl_output->output_ctx = output_ctx;
    TAILQ_INSERT_TAIL(&output_free_list, fl_output, entries);
}


static int GetRunModeOutputPriority(RunModeOutput *module)
{
    TmModule *tm = TmModuleGetByName(module->name);
    if (tm == NULL)
        return 0;

    return tm->priority;
}

static void InsertInRunModeOutputs(RunModeOutput *runmode_output)
{
    RunModeOutput *r_output = NULL;
    int output_priority = GetRunModeOutputPriority(runmode_output);

    TAILQ_FOREACH(r_output, &RunModeOutputs, entries) {
        if (GetRunModeOutputPriority(r_output) < output_priority)
            break;
    }
    if (r_output) {
        TAILQ_INSERT_BEFORE(r_output, runmode_output, entries);
    } else {
        TAILQ_INSERT_TAIL(&RunModeOutputs, runmode_output, entries);
    }
}

/** \brief Turn output into thread module */
static void SetupOutput(const char *name, OutputModule *module, OutputCtx *output_ctx)
{
    /* flow logger doesn't run in the packet path */
    if (module->FlowLogFunc) {
        OutputRegisterFlowLogger(module->name, module->FlowLogFunc, output_ctx);
        return;
    }
    /* stats logger doesn't run in the packet path */
    if (module->StatsLogFunc) {
        OutputRegisterStatsLogger(module->name, module->StatsLogFunc, output_ctx);
        return;
    }

    TmModule *tm_module = TmModuleGetByName(module->name);
    if (tm_module == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                "TmModuleGetByName for %s failed", module->name);
        exit(EXIT_FAILURE);
    }
    if (strcmp(tmm_modules[TMM_ALERTDEBUGLOG].name, tm_module->name) == 0)
        debuglog_enabled = 1;

    if (module->PacketLogFunc) {
        SCLogDebug("%s is a packet logger", module->name);
        OutputRegisterPacketLogger(module->name, module->PacketLogFunc,
                module->PacketConditionFunc, output_ctx);

        /* need one instance of the packet logger module */
        if (pkt_logger_module == NULL) {
            pkt_logger_module = TmModuleGetByName("__packet_logger__");
            if (pkt_logger_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "TmModuleGetByName for __packet_logger__ failed");
                exit(EXIT_FAILURE);
            }

            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (unlikely(runmode_output == NULL))
                return;
            runmode_output->name = module->name;
            runmode_output->tm_module = pkt_logger_module;
            runmode_output->output_ctx = NULL;
            InsertInRunModeOutputs(runmode_output);
            SCLogDebug("__packet_logger__ added");
        }
    } else if (module->TxLogFunc) {
        SCLogDebug("%s is a tx logger", module->name);
        OutputRegisterTxLogger(module->name, module->alproto,
                module->TxLogFunc, output_ctx);

        /* need one instance of the tx logger module */
        if (tx_logger_module == NULL) {
            tx_logger_module = TmModuleGetByName("__tx_logger__");
            if (tx_logger_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "TmModuleGetByName for __tx_logger__ failed");
                exit(EXIT_FAILURE);
            }

            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (unlikely(runmode_output == NULL))
                return;
            runmode_output->name = module->name;
            runmode_output->tm_module = tx_logger_module;
            runmode_output->output_ctx = NULL;
            InsertInRunModeOutputs(runmode_output);
            SCLogDebug("__tx_logger__ added");
        }
    } else if (module->FiledataLogFunc) {
        SCLogDebug("%s is a filedata logger", module->name);
        OutputRegisterFiledataLogger(module->name, module->FiledataLogFunc, output_ctx);

        /* need one instance of the tx logger module */
        if (filedata_logger_module == NULL) {
            filedata_logger_module = TmModuleGetByName("__filedata_logger__");
            if (filedata_logger_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "TmModuleGetByName for __filedata_logger__ failed");
                exit(EXIT_FAILURE);
            }

            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (unlikely(runmode_output == NULL))
                return;
            runmode_output->name = module->name;
            runmode_output->tm_module = filedata_logger_module;
            runmode_output->output_ctx = NULL;
            InsertInRunModeOutputs(runmode_output);
            SCLogDebug("__filedata_logger__ added");
        }
    } else if (module->FileLogFunc) {
        SCLogDebug("%s is a file logger", module->name);
        OutputRegisterFileLogger(module->name, module->FileLogFunc, output_ctx);

        /* need one instance of the tx logger module */
        if (file_logger_module == NULL) {
            file_logger_module = TmModuleGetByName("__file_logger__");
            if (file_logger_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "TmModuleGetByName for __file_logger__ failed");
                exit(EXIT_FAILURE);
            }

            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (unlikely(runmode_output == NULL))
                return;
            runmode_output->name = module->name;
            runmode_output->tm_module = file_logger_module;
            runmode_output->output_ctx = NULL;
            InsertInRunModeOutputs(runmode_output);
            SCLogDebug("__file_logger__ added");
        }
    } else if (module->StreamingLogFunc) {
        SCLogDebug("%s is a streaming logger", module->name);
        OutputRegisterStreamingLogger(module->name, module->StreamingLogFunc,
                output_ctx, module->stream_type);

        /* need one instance of the streaming logger module */
        if (streaming_logger_module == NULL) {
            streaming_logger_module = TmModuleGetByName("__streaming_logger__");
            if (streaming_logger_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "TmModuleGetByName for __streaming_logger__ failed");
                exit(EXIT_FAILURE);
            }

            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (unlikely(runmode_output == NULL))
                return;
            runmode_output->name = module->name;
            runmode_output->tm_module = streaming_logger_module;
            runmode_output->output_ctx = NULL;
            InsertInRunModeOutputs(runmode_output);
            SCLogDebug("__streaming_logger__ added");
        }
    } else {
        SCLogDebug("%s is a regular logger", module->name);

        RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
        if (unlikely(runmode_output == NULL))
            return;
        runmode_output->name = module->name;
        runmode_output->tm_module = tm_module;
        runmode_output->output_ctx = output_ctx;
        InsertInRunModeOutputs(runmode_output);
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
    const char *enabled;
    char tls_log_enabled = 0;
    char tls_store_present = 0;

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

        if (strncmp(output->val, "unified-", sizeof("unified-") - 1) == 0) {
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "Unified1 is no longer supported,"
                    " use Unified2 instead "
                    "(see https://redmine.openinfosecfoundation.org/issues/353"
                    " for an explanation)");
            continue;
        } else if (strcmp(output->val, "alert-prelude") == 0) {
#ifndef PRELUDE
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "Prelude support not compiled in. Reconfigure/"
                    "recompile with --enable-prelude to add Prelude "
                    "support.");
            continue;
#endif
        } else if (strcmp(output->val, "eve-log") == 0) {
#ifndef HAVE_LIBJANSSON
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "Eve-log support not compiled in. Reconfigure/"
                    "recompile with libjansson and its development "
                    "files installed to add eve-log support.");
            continue;
#endif
        } else if (strcmp(output->val, "lua") == 0) {
#ifndef HAVE_LUA
            SCLogWarning(SC_ERR_NOT_SUPPORTED,
                    "lua support not compiled in. Reconfigure/"
                    "recompile with lua(jit) and its development "
                    "files installed to add lua support.");
            continue;
#endif
        } else if (strcmp(output->val, "tls-log") == 0) {
            tls_log_enabled = 1;
        }

        OutputModule *module = OutputGetModuleByConfName(output->val);
        if (module == NULL) {
            FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                "No output module named %s", output->val);
            continue;
        }

        OutputCtx *output_ctx = NULL;
        if (module->InitFunc != NULL) {
            output_ctx = module->InitFunc(output_config);
            if (output_ctx == NULL) {
                FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT, "output module setup failed");
                continue;
            }
        } else if (module->InitSubFunc != NULL) {
            SCLogInfo("skipping submodule");
            continue;
        }

        // TODO if module == parent, find it's children
        if (strcmp(output->val, "eve-log") == 0) {
            ConfNode *types = ConfNodeLookupChild(output_config, "types");
            SCLogDebug("types %p", types);
            if (types != NULL) {
                ConfNode *type = NULL;
                TAILQ_FOREACH(type, &types->head, next) {
                    SCLogInfo("enabling 'eve-log' module '%s'", type->val);

                    char subname[256];
                    snprintf(subname, sizeof(subname), "%s.%s", output->val, type->val);

                    OutputModule *sub_module = OutputGetModuleByConfName(subname);
                    if (sub_module == NULL) {
                        FatalErrorOnInit(SC_ERR_INVALID_ARGUMENT,
                                "No output module named %s", subname);
                        continue;
                    }
                    if (sub_module->parent_name == NULL ||
                            strcmp(sub_module->parent_name,output->val) != 0) {
                        FatalError(SC_ERR_INVALID_ARGUMENT,
                                "bad parent for %s", subname);
                    }
                    if (sub_module->InitSubFunc == NULL) {
                        FatalError(SC_ERR_INVALID_ARGUMENT,
                                "bad sub-module for %s", subname);
                    }
                    ConfNode *sub_output_config = ConfNodeLookupChild(type, type->val);
                    // sub_output_config may be NULL if no config

                    /* pass on parent output_ctx */
                    OutputCtx *sub_output_ctx =
                        sub_module->InitSubFunc(sub_output_config, output_ctx);
                    if (sub_output_ctx == NULL) {
                        continue;
                    }

                    AddOutputToFreeList(sub_module, sub_output_ctx);
                    SetupOutput(sub_module->name, sub_module, sub_output_ctx);
                }
            }
            /* add 'eve-log' to free list as it's the owner of the
             * main output ctx from which the sub-modules share the
             * LogFileCtx */
            AddOutputToFreeList(module, output_ctx);

        } else if (strcmp(output->val, "lua") == 0) {
            SCLogDebug("handle lua");

            ConfNode *scripts = ConfNodeLookupChild(output_config, "scripts");
            BUG_ON(scripts == NULL); //TODO

            OutputModule *m;
            TAILQ_FOREACH(m, &output_ctx->submodules, entries) {
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
                OutputCtx *sub_output_ctx =
                    m->InitSubFunc(script, output_ctx);
                if (sub_output_ctx == NULL) {
                    SCLogInfo("sub_output_ctx NULL, skipping");
                    continue;
                }

                SetupOutput(m->name, m, sub_output_ctx);
            }

        } else {
            AddOutputToFreeList(module, output_ctx);
            SetupOutput(module->name, module, output_ctx);
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
                    output_ctx = module->InitFunc(output_config);
                    if (output_ctx == NULL) {
                        continue;
                    }
                }

                AddOutputToFreeList(module, output_ctx);
                SetupOutput(module->name, module, output_ctx);
            }
        }
    }

}

/**
 * Setup the outputs for this run mode.
 *
 * \param tv The ThreadVars for the thread the outputs will be
 * appended to.
 */
void SetupOutputs(ThreadVars *tv)
{
    RunModeOutput *output;
    TAILQ_FOREACH(output, &RunModeOutputs, entries) {
        tv->cap_flags |= output->tm_module->cap_flags;
        TmSlotSetFuncAppend(tv, output->tm_module, output->output_ctx);
    }
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
}
