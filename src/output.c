/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#include "suricata-common.h"
#include "flow.h"
#include "conf.h"
#include "tm-modules.h"
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
    if (module == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocated memory for new output module");
        exit(EXIT_FAILURE);
    }

    module->name = SCStrdup(name);
    module->conf_name = SCStrdup(conf_name);
    module->InitFunc = InitFunc;
    TAILQ_INSERT_TAIL(&output_modules, module, entries);

    SCLogInfo("Output module \"%s\" registered.", name);
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
