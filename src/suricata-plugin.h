/* Copyright (C) 2020-2022 Open Information Security Foundation
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

#ifndef __SURICATA_PLUGIN_H__
#define __SURICATA_PLUGIN_H__

#include <stdint.h>
#include <stdbool.h>

#include "conf.h"

/**
 * The size of the data chunk inside each packet structure a plugin
 * has for private data (Packet->plugin_v).
 */
#define PLUGIN_VAR_SIZE 64

/**
 * Structure to define a Suricata plugin.
 */
typedef struct SCPlugin_ {
    const char *name;
    const char *license;
    const char *author;
    void (*Init)(void);
} SCPlugin;

typedef SCPlugin *(*SCPluginRegisterFunc)(void);

/**
 * Structure used to define an Eve output file type plugin.
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
    TAILQ_ENTRY(SCEveFileType_) entries;
} SCEveFileType;

bool SCPluginRegisterEveFileType(SCEveFileType *);
bool SCRegisterEveFileType(SCEveFileType *);

typedef struct SCCapturePlugin_ {
    char *name;
    void (*Init)(const char *args, int plugin_slot, int receive_slot, int decode_slot);
    int (*ThreadInit)(void *ctx, int thread_id, void **thread_ctx);
    int (*ThreadDeinit)(void *ctx, void *thread_ctx);
    const char *(*GetDefaultMode)(void);
    TAILQ_ENTRY(SCCapturePlugin_) entries;
} SCCapturePlugin;

int SCPluginRegisterCapture(SCCapturePlugin *);

#endif /* __SURICATA_PLUGIN_H */
