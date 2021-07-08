/* Copyright (C) 2021 Open Information Security Foundation
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

#include "suricata-common.h"
#include "output-json-filetypes.h"

typedef struct EveFileType_ {
    SCEveFileType *file_type;
    TAILQ_ENTRY(EveFileType_) entries;
} EveFileType;

static TAILQ_HEAD(, EveFileType_) output_types = TAILQ_HEAD_INITIALIZER(output_types);

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

/**
 * \brief Register an Eve file type.
 *
 * \retval true if registered successfully, false if the file type name
 *      conflicts with a built-in or previously registered
 *      file type.
 */
bool SCRegisterEveFileType(SCEveFileType *file_type)
{
    /* First check that the name doesn't conflict with a built-in filetype. */
    if (IsBuiltinTypeName(file_type->name)) {
        SCLogError(SC_ERR_LOG_OUTPUT, "Eve file type name conflicts with built-in type: %s",
                file_type->name);
        return false;
    }

    /* Now check against previously registered file types. */
    EveFileType *existing = NULL;
    TAILQ_FOREACH (existing, &output_types, entries) {
        if (strcmp(existing->file_type->name, file_type->name) == 0) {
            SCLogError(SC_ERR_LOG_OUTPUT,
                    "Eve file type name conflicts with previously registered type: %s",
                    existing->file_type->name);
            return false;
        }
    }

    /* Wrap and register. */
    EveFileType *new = SCCalloc(1, sizeof(*new));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for eve file type: %s",
                file_type->name);
        return false;
    }
    new->file_type = file_type;

    SCLogDebug("Registering EVE file type plugin %s", file_type->name);
    TAILQ_INSERT_TAIL(&output_types, new, entries);
    return true;
}

SCEveFileType *SCEveFindFileType(const char *name)
{
    EveFileType *file_type = NULL;
    TAILQ_FOREACH (file_type, &output_types, entries) {
        if (strcmp(name, file_type->file_type->name) == 0) {
            return file_type->file_type;
        }
    }
    return NULL;
}
