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
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "log-httplog.h"

#include "output.h"

#include "cuda-packet-batcher.h"

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
    int (*RunModeFunc)(DetectEngineCtx *);
} RunMode;

typedef struct RunModes_ {
    int no_of_runmodes;
    RunMode *runmodes;
} RunModes;

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

static RunModes runmodes[RUNMODE_MAX];

static char *active_runmode;

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
 * \param de_ctx             Detection Engine Context.
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
           "RunMode Type", "Custom Mode ", "Descripition");
    printf("|-----------------------------------------------------------------"
           "-----------------------\n");
    int i = RUNMODE_UNKNOWN + 1;
    int j = 0;
    for ( ; i < RUNMODE_MAX; i++) {
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
        printf("|-----------------------------------------------------------------"
               "-----------------------\n");
    }

    return;
}

void RunModeDispatch(int runmode, const char *custom_mode, DetectEngineCtx *de_ctx)
{
    if (custom_mode == NULL) {
        char *val = NULL;
        if (ConfGet("runmode", &val) != 1) {
            custom_mode = NULL;
        } else {
            custom_mode = val;
        }
    }

    if (custom_mode == NULL) {
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
            case RUNMODE_NAPATECH:
                custom_mode = RunModeNapatechGetDefaultMode();
                break;
            case RUNMODE_AFP_DEV:
                custom_mode = RunModeAFPGetDefaultMode();
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
            custom_mode = SCStrdup("workers");
        }
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
    active_runmode = SCStrdup(custom_mode);

    mode->RunModeFunc(de_ctx);

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
                               int (*RunModeFunc)(DetectEngineCtx *))
{
    if (RunModeGetCustomMode(runmode, name) != NULL) {
        SCLogError(SC_ERR_RUNMODE, "A runmode by this custom name has already "
                   "been registered.  Please use an unique name");
        return;
    }

    runmodes[runmode].runmodes =
        SCRealloc(runmodes[runmode].runmodes,
                  (runmodes[runmode].no_of_runmodes + 1) * sizeof(RunMode));
    if (runmodes[runmode].runmodes == NULL) {
        exit(EXIT_FAILURE);
    }

    RunMode *mode = &runmodes[runmode].runmodes[runmodes[runmode].no_of_runmodes];
    runmodes[runmode].no_of_runmodes++;

    mode->runmode = runmode;
    mode->name = SCStrdup(name);
    mode->description = SCStrdup(description);
    mode->RunModeFunc = RunModeFunc;

    return;
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

        output_config = ConfNodeLookupChild(output, output->val);
        if (output_config == NULL) {
            /* Shouldn't happen. */
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                "Failed to lookup configuration child node: fast");
            exit(1);
        }

        enabled = ConfNodeLookupChildValue(output_config, "enabled");
        if (enabled == NULL || !ConfValIsTrue(enabled)) {
            continue;
        }

        if (strncmp(output->val, "unified-", sizeof("unified-") - 1) == 0) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Unified1 is no longer supported,"
                    " use Unified2 instead "
                    "(see https://redmine.openinfosecfoundation.org/issues/353"
                    " for an explanation)");
            continue;
        } else if (strcmp(output->val, "alert-prelude") == 0) {
#ifndef PRELUDE
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Prelude support not compiled in. Reconfigure/"
                    "recompile with --enable-prelude to add Prelude "
                    "support.");
            continue;
#endif
        }

        OutputModule *module = OutputGetModuleByConfName(output->val);
        if (module == NULL) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "No output module named %s, ignoring", output->val);
            continue;
        }

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
        if (strcmp(tmm_modules[TMM_ALERTDEBUGLOG].name, tm_module->name) == 0)
            debuglog_enabled = 1;

        RunModeOutput *runmode_output = SCCalloc(1, sizeof(RunModeOutput));
        if (runmode_output == NULL)
            return;
        runmode_output->tm_module = tm_module;
        runmode_output->output_ctx = output_ctx;
        TAILQ_INSERT_TAIL(&RunModeOutputs, runmode_output, entries);
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
 * Initialize the output modules.
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
        threading_detect_ratio = 1;
    }

    SCLogDebug("threading.detect-thread-ratio %f", threading_detect_ratio);
}
