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
 * A list of output modules that will be active for the run mode.
 */
typedef struct RunModeOutput_ {
    TmModule *tm_module;
    OutputCtx *output_ctx;

    TAILQ_ENTRY(RunModeOutput_) entries;
} RunModeOutput;
TAILQ_HEAD(, RunModeOutput_) RunModeOutputs =
    TAILQ_HEAD_INITIALIZER(RunModeOutputs);

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
