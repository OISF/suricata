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

#ifndef __SC_OUTPUT_JSON_FILETYPES_H__
#define __SC_OUTPUT_JSON_FILETYPES_H__

#include <stdbool.h>

/**
 * Forward declaration of ConfNode as the configuration API is still private at
 * this time. Users can include <suricata/private/conf.h> if they need to access
 * this data type now.
 */
typedef struct ConfNode_ ConfNode;

/**
 * Struct defining an Eve file type.
 */
typedef struct SCEveFileType_ {
    /* The name of the output, used to specify the output in the filetype section
     * of the eve-log configuration. */
    const char *name;
    /* Init Called on first access */
    int (*Init)(ConfNode *conf, bool threaded, void **init_data);
    /* Write - Called on each write to the object */
    int (*Write)(const char *buffer, int buffer_len, void *init_data, void *thread_data);
    /* Close - Called on final close */
    void (*Deinit)(void *init_data);
    /* ThreadInit - Called for each thread using file object*/
    int (*ThreadInit)(void *init_data, int thread_id, void **thread_data);
    /* ThreadDeinit - Called for each thread using file object */
    int (*ThreadDeinit)(void *init_data, void *thread_data);
} SCEveFileType;

bool SCRegisterEveFileType(SCEveFileType *file_type);
SCEveFileType *SCEveFindFileType(const char *name);

#endif /* ! __SC_OUTOUT_JSON_FILETYPES_H__ */
