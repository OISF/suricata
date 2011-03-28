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

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified-log.h"
#include "alert-unified-alert.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "output.h"

#include "cuda-packet-batcher.h"

#include "source-pfring.h"

/**
 * \brief Holds description for a runmode.
 */
typedef struct RunMode_ {
    /* unique custom id generated for this runmode */
    int custom_id;
    /* the runmode type */
    int runmode;
    const char *name;
    const char *description;
    /* runmode function */
    int (*RunModeFunc)(DetectEngineCtx *);
} RunMode;

/**
 * A list of output modules that will be active for the run mode.
 */
typedef struct RunModeOutput_ {
    TmModule *tm_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(RunModeOutput_) entries;
} RunModeOutput;
TAILQ_HEAD(, RunModeOutput_) RunModeOutputs =
    TAILQ_HEAD_INITIALIZER(RunModeOutputs);

/* unique key used to generate runmode custom ids */
static int runmode_id = 0;
RunMode *runmodes = NULL;

/**
 * \internal
 * \brief Check if a runmode custom id is valid.
 *
 * \param runmode_custom_id The id to be validated.
 *
 * \retval 1 If true.
 * \retval 0 Otherwise.
 */
int RunModeCustomIdValid(int runmode_custom_id)
{
    if (runmode_custom_id < 0 || runmode_custom_id >= runmode_id) {
        return 0;
    }

    return 1;
}

/**
 * \brief Register all runmodes in the engine.
 */
void RunModeRegisterRunModes(void)
{
    RunModeIdsPcapRegister();
    RunModeFilePcapRegister();
    RunModeIdsPfringRegister();
    RunModeIpsNFQRegister();
    RunModeIpsIPFWRegister();
    RunModeErfFileRegister();
    RunModeErfDagRegister();
    UtRunModeRegister();

    return;
}

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
            break;
        case RUNMODE_PCAP_FILE:
            return "PCAP_FILE";
            break;
        case RUNMODE_PFRING:
#ifdef HAVE_PFRING
            return "PFRING";
#else
            return "PFRING(DISABLED)";
#endif
            break;
        case RUNMODE_NFQ:
            return "NFQ";
            break;
        case RUNMODE_IPFW:
            return "IPFW";
            break;
        case RUNMODE_ERF_FILE:
            return "ERF_FILE";
            break;
        case RUNMODE_DAG:
            return "ERF_DAG";
            break;
        case RUNMODE_UNITTEST:
            return "UNITTEST";
            break;
        default:
            SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
            exit(EXIT_FAILURE);
    }
}

/**
 * \brief Lists all registered runmodes.
 */
void RunModeListRunmodes(void)
{
    printf("------------------------------------------------------------------"
           "-----------------------\n");
    printf("--------------------------------------Runmodes--------------------"
           "-----------------------\n");
    printf("------------------------------------------------------------------"
           "-----------------------\n");

    printf("| %-2s | %-17s | %-17s | %-10s \n",
           "Id", "    Mode", "  Name-", "Descripition");
    printf("|-----------------------------------------------------------------"
           "-----------------------\n");
    int i;
    for (i = 0; i < runmode_id; i++) {
        printf("| %-2d | %-17s | %-17s | %-27s \n",
               i,
               RunModeTranslateModeToName(runmodes[i].runmode),
               runmodes[i].name,
               runmodes[i].description);
    }
    printf("|-----------------------------------------------------------------"
           "-----------------------\n");

    return;
}

/**
 * \brief Dispatcher function for runmodes.  Calls the required runmode function
 *        based on runmode + runmode_custom_id.
 *
 * \param runmode            The runmode type.
 * \param runmode_customd_id The runmode custom id.
 * \param de_ctx             Detection Engine Context.
 */
void RunModeDispatch(int runmode, int runmode_custom_id, DetectEngineCtx *de_ctx)
{
    if (runmode_custom_id != -1 &&
        (runmode_custom_id < 0 || runmode_custom_id >= runmode_id)) {
        SCLogError(SC_ERR_RUNMODE, "You have supplied wrong runmode type - "
                   "%d", runmode_custom_id);
        exit(EXIT_FAILURE);
    }

    if (runmode_custom_id != -1) {
        if (runmode != runmodes[runmode_custom_id].runmode) {
            SCLogError(SC_ERR_RUNMODE, "The runmode custom id's(%d) "
                       "runmode - \"%s\" doesn't match the runmode type - \"%s\" "
                       "being used.  Please use runmode id whose RunMode "
                       "mode matches the mode you are running the "
                       "engine in.",
                       runmode_custom_id,
                       RunModeTranslateModeToName(runmodes[runmode_custom_id].runmode),
                       RunModeTranslateModeToName(runmode));
            exit(EXIT_FAILURE);
        }
        runmodes[runmode_custom_id].RunModeFunc(de_ctx);
        return;
    }

    switch (runmode) {
        case RUNMODE_PCAP_DEV:
            runmode_custom_id = RunModeIdsGetDefaultMode();
            break;
        case RUNMODE_PCAP_FILE:
            runmode_custom_id = RunModeFilePcapGetDefaultMode();
            break;
#ifdef HAVE_PFRING
        case RUNMODE_PFRING:
            runmode_custom_id = RunModeIdsPfringGetDefaultMode();
            break;
#endif
        case RUNMODE_NFQ:
            runmode_custom_id = RunModeIpsNFQGetDefaultMode();
            break;
        case RUNMODE_IPFW:
            runmode_custom_id = RunModeIpsIPFWGetDefaultMode();
            break;
        case RUNMODE_ERF_FILE:
            runmode_custom_id = RunModeErfFileGetDefaultMode();
            break;
        case RUNMODE_DAG:
            runmode_custom_id = RunModeErfDagGetDefaultMode();
            break;
        default:
            SCLogError(SC_ERR_UNKNOWN_RUN_MODE, "Unknown runtime mode. Aborting");
            exit(EXIT_FAILURE);
    }

    if (runmode_custom_id < 0 && runmode_custom_id >= runmode_id) {
        SCLogError(SC_ERR_RUNMODE, "Wrong default custom id - %d, returned by "
                   "runmode - %d", runmode_custom_id, runmode);
    }

    runmodes[runmode_custom_id].RunModeFunc(de_ctx);

    return;
}

/**
 * \brief Registers a new runmode.
 *
 * \param runmode     Runmode type.
 * \param name        Simple name.  Need not be unique, although suggested.
 * \param description Description for this runmode.
 * \param RunModeFunc The function to be run for this runmode.
 */
int RunModeRegisterNewRunMode(uint8_t runmode, const char *name,
                              const char *description,
                              int (*RunModeFunc)(DetectEngineCtx *))
{
    runmodes = SCRealloc(runmodes, (runmode_id + 1) * sizeof(RunMode));
    if (runmodes == NULL) {
        exit(EXIT_FAILURE);
    }
    runmodes[runmode_id].custom_id = runmode_id;
    runmodes[runmode_id].runmode = runmode;
    runmodes[runmode_id].name = SCStrdup(name);
    runmodes[runmode_id].description = SCStrdup(description);
    runmodes[runmode_id].RunModeFunc = RunModeFunc;
    runmode_id++;

    return runmode_id - 1;
}

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
        if (output->output_ctx != NULL && output->output_ctx->DeInit != NULL)
            output->output_ctx->DeInit(output->output_ctx);
        SCFree(output);
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

        if (strcmp(output->val, "stats") == 0)
            continue;

        OutputModule *module = OutputGetModuleByConfName(output->val);
        if (module == NULL) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "No output module named %s, ignoring", output->val);
            continue;
        }

        output_config = ConfNodeLookupChild(output, module->conf_name);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to lookup configuration child node: fast");
            exit(1);
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled != NULL && strcasecmp(enabled, "yes") == 0) {
            OutputCtx *output_ctx = NULL;
            if (module->InitFunc != NULL) {
                output_ctx = module->InitFunc(output_config);
                if (output_ctx == NULL) {
                    /* In most cases the init function will have logged the
                     * error. Maybe we should exit on init errors? */
                    continue;
                }
            }
            tm_module = TmModuleGetByName(module->name);
            if (tm_module == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", module->name);
                exit(EXIT_FAILURE);
            }
            RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
            if (runmode_output == NULL)
                return;
            runmode_output->tm_module = tm_module;
            runmode_output->output_ctx = output_ctx;
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
void SetupOutputs(ThreadVars *tv)
{
    RunModeOutput *output;
    TAILQ_FOREACH(output, &RunModeOutputs, entries) {
        tv->cap_flags |= output->tm_module->cap_flags;
        TmVarSlotSetFuncAppend(tv, output->tm_module, output->output_ctx);
    }
}

float threading_detect_ratio = 1;

/**
 * Initialize the output modules.
 */
void RunModeInitialize(void)
{
    threading_set_cpu_affinity = FALSE;
    if ((ConfGetBool("threading.set_cpu_affinity", &threading_set_cpu_affinity)) == 0) {
        threading_set_cpu_affinity = FALSE;
    }
    /* try to get custom cpu mask value if needed */
    if (threading_set_cpu_affinity == TRUE) {
        AffinitySetupLoadFromConfig();
    }
    if ((ConfGetFloat("threading.detect_thread_ratio", &threading_detect_ratio)) != 1) {
        threading_detect_ratio = 1;
    }

    SCLogDebug("threading_detect_ratio %f", threading_detect_ratio);
}
