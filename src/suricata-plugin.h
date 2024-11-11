/* Copyright (C) 2020-2021 Open Information Security Foundation
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

#ifndef SURICATA_SURICATA_PLUGIN_H
#define SURICATA_SURICATA_PLUGIN_H

#include <stdint.h>
#include <stdbool.h>

#include "queue.h"

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

typedef struct SCCapturePlugin_ {
    char *name;
    void (*Init)(const char *args, int plugin_slot, int receive_slot, int decode_slot);
    int (*ThreadInit)(void *ctx, int thread_id, void **thread_ctx);
    int (*ThreadDeinit)(void *ctx, void *thread_ctx);
    const char *(*GetDefaultMode)(void);
    TAILQ_ENTRY(SCCapturePlugin_) entries;
} SCCapturePlugin;

int SCPluginRegisterCapture(SCCapturePlugin *);

typedef struct SCAppLayerPlugin_ {
    char *name;
    char *logname;
    char *confname;
    void (*Register)(void);
    bool (*Logger)(void *tx, void *jb);
    void (*KeywordsRegister)(void);
} SCAppLayerPlugin;

int SCPluginRegisterAppLayer(SCAppLayerPlugin *);

#endif /* __SURICATA_PLUGIN_H */
