/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * File-like output for logging: null/discard device
 */

#include "suricata-common.h" /* errno.h, string.h, etc. */

#include "output.h" /* DEFAULT_LOG_* */
#include "output-eve-null.h"

#ifdef OS_WIN32
void NullLogInitialize(void)
{
}
#else /* !OS_WIN32 */

#define OUTPUT_NAME "nullsink"

static int NullLogInit(ConfNode *conf, bool threaded, void **init_data)
{
    *init_data = NULL;
    return 0;
}

static int NullLogWrite(const char *buffer, int buffer_len, void *init_data, void *thread_data)
{
    return 0;
}

static int NullLogThreadInit(void *init_data, ThreadId thread_id, void **thread_data)
{
    *thread_data = NULL;
    return 0;
}

static int NullLogThreadDeInit(void *init_data, void *thread_data)
{
    return 0;
}

static void NullLogDeInit(void *init_data)
{
}

void NullLogInitialize(void)
{
    SCLogDebug("Registering the %s logger", OUTPUT_NAME);

    SCEveFileType *file_type = SCCalloc(1, sizeof(SCEveFileType));

    if (file_type == NULL) {
        FatalError("Unable to allocate memory for eve file type %s", OUTPUT_NAME);
    }

    file_type->name = OUTPUT_NAME;
    file_type->Init = NullLogInit;
    file_type->Deinit = NullLogDeInit;
    file_type->Write = NullLogWrite;
    file_type->ThreadInit = NullLogThreadInit;
    file_type->ThreadDeinit = NullLogThreadDeInit;
    if (!SCRegisterEveFileType(file_type)) {
        FatalError("Failed to register EVE file type: %s", OUTPUT_NAME);
    }
}
#endif /* !OS_WIN32 */
