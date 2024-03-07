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

/**
 * \file
 *
 * \brief EVE logging subsystem
 *
 * This file will attempt to the main module for EVE logging
 * sub-system. Currently most of the API resides in output-json.[ch],
 * but due to some circular dependencies between EVE, and LogFileCtx,
 * it made it hard to add EVE filetype modules there until some
 * include issues are figured out.
 */

#ifndef __SURICATA_OUTPUT_EVE_H__
#define __SURICATA_OUTPUT_EVE_H__

#include "suricata-common.h"
#include "conf.h"

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

bool SCRegisterEveFileType(SCEveFileType *);

SCEveFileType *SCEveFindFileType(const char *name);

#endif
