/* Copyright (C) 2024 Open Information Security Foundation
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

#include "output-eve.h"
#include "util-debug.h"

static TAILQ_HEAD(, SCEveFileType_) output_types = TAILQ_HEAD_INITIALIZER(output_types);

static bool IsBuiltinTypeName(const char *name)
{
    const char *builtin[] = {
        "regular",
        "unix_dgram",
        "unix_stream",
        "redis",
        NULL,
    };
    for (int i = 0;; i++) {
        if (builtin[i] == NULL) {
            break;
        }
        if (strcmp(builtin[i], name) == 0) {
            return true;
        }
    }
    return false;
}

SCEveFileType *SCEveFindFileType(const char *name)
{
    SCEveFileType *plugin = NULL;
    TAILQ_FOREACH (plugin, &output_types, entries) {
        if (strcmp(name, plugin->name) == 0) {
            return plugin;
        }
    }
    return NULL;
}

/**
 * \brief Register an Eve file type.
 *
 * \retval true if registered successfully, false if the file type name
 *      conflicts with a built-in or previously registered
 *      file type.
 */
bool SCRegisterEveFileType(SCEveFileType *plugin)
{
    /* First check that the name doesn't conflict with a built-in filetype. */
    if (IsBuiltinTypeName(plugin->name)) {
        SCLogError("Eve file type name conflicts with built-in type: %s", plugin->name);
        return false;
    }

    /* Now check against previously registered file types. */
    SCEveFileType *existing = NULL;
    TAILQ_FOREACH (existing, &output_types, entries) {
        if (strcmp(existing->name, plugin->name) == 0) {
            SCLogError("Eve file type name conflicts with previously registered type: %s",
                    plugin->name);
            return false;
        }
    }

    SCLogDebug("Registering EVE file type plugin %s", plugin->name);
    TAILQ_INSERT_TAIL(&output_types, plugin, entries);
    return true;
}
