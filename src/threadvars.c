/* Copyright (C) 2026 Open Information Security Foundation
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
#include "threadvars.h"
#include "thread-storage.h"

/**
 * \brief Allocate a new ThreadVars structure.
 *
 * \retval NULL if allocation failed.
 * \retval Pointer to newly allocated ThreadVars structure.
 */
ThreadVars *ThreadVarsAlloc(void)
{
    ThreadVars *tv = SCCalloc(1, sizeof(ThreadVars) + SCThreadStorageSize());
    if (tv == NULL)
        return NULL;
    SC_ATOMIC_INIT(tv->flags);
    return tv;
}

/**
 * \brief Free a ThreadVars structure.
 *
 * \param tv Pointer to ThreadVars structure to be freed.
 */
void ThreadVarsFree(ThreadVars *tv)
{
    if (tv == NULL)
        return;
    SCFree(tv);
}
