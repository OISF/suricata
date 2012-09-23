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
 * \brief Register an output module.
 *
 * This function will register an output module so it can be
 * configured with the configuration file.
 *
 * \retval Returns 0 on success, -1 on failure.
 */
void
OutputRegisterModule(char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *))
{
    OutputModule *module = SCCalloc(1, sizeof(*module));
    if (unlikely(module == NULL)) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in OutputRegisterModule. Exiting...");
        exit(EXIT_FAILURE);
    }

    module->name = SCStrdup(name);
    module->conf_name = SCStrdup(conf_name);
    module->InitFunc = InitFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogDebug("Output module \"%s\" registered.", name);
}

/**
 * \brief Get an output module by name.
 *
 * \retval The OutputModule with the given name or NULL if no output module
 * with the given name is registered.
 */
OutputModule *
OutputGetModuleByConfName(char *conf_name)
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
        SCFree(module->name);
        SCFree(module->conf_name);
        SCFree(module);
    }
}
