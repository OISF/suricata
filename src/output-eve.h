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

#ifndef SURICATA_OUTPUT_EVE_H
#define SURICATA_OUTPUT_EVE_H

#include "suricata-common.h"
#include "conf.h"

typedef uint32_t ThreadId;

/**
 * \brief Structure used to define an EVE output file type plugin.
 *
 * EVE filetypes implement an object with a file-like interface and
 * are used to output EVE log records to files, syslog, or
 * database. They can be built-in such as the syslog (see
 * SyslogInitialize()) and nullsink (see NullLogInitialize()) outputs,
 * registered by a library user or dynamically loaded as a plugin.
 *
 * The life cycle of an EVE filetype is:
 *   - Init: called once for each EVE instance using this filetype
 *   - ThreadInit: called once for each output thread
 *   - Write: called for each log record
 *   - ThreadInit: called once for each output thread on exit
 *   - Deinit: called once for each EVE instance using this filetype on exit
 *
 * Examples:
 * - built-in syslog: \ref src/output-eve-syslog.c
 * - built-in nullsink: \ref src/output-eve-null.c
 * - example plugin: \ref examples/plugins/c-json-filetype/filetype.c
 *
 * ### Multi-Threaded Note:
 *
 * The EVE logging system can be configured by the Suricata user to
 * run in threaded or non-threaded modes. In the default non-threaded
 * mode, ThreadInit will only be called once and the filetype does not
 * need to be concerned with threads.
 *
 * However, in **threaded** mode, ThreadInit will be called multiple
 * times and the filetype needs to be thread aware and thread-safe. If
 * utilizing a unique resource such as afile for each thread then you
 * may be naturally thread safe. However, if sharing a single file
 * handle across all threads then your filetype will have to take care
 * of locking, etc.
 */
typedef struct SCEveFileType_ {
    /**
     * \brief The name of the output, used in the configuration.
     *
     * This name is used by the configuration file to specify the EVE
     * filetype used.
     *
     * For example:
     *
     * \code{.yaml}
     * outputs:
     *   - eve-log:
     *       filetype: my-output-name
     * \endcode
     */
    const char *name;

    /**
     * \brief Function to initialize this filetype.
     *
     * \param conf The ConfNode of the `eve-log` configuration
     *     section this filetype is being initialized for
     *
     * \param threaded Flag to specify if the EVE sub-systems is in
     *     threaded mode or not
     *
     * \param init_data An output pointer for filetype specific data
     *
     * \retval 0 on success, -1 on failure
     */
    int (*Init)(ConfNode *conf, bool threaded, void **init_data);

    /**
     * \brief Called for each EVE log record.
     *
     * The Write function is called for each log EVE log record. The
     * provided buffer contains a fully formatted EVE record in JSON
     * format.
     *
     * \param buffer The fully formatted JSON EVE log record
     *
     * \param buffer_len The length of the buffer
     *
     * \param init_data The data setup in the call to Init
     *
     * \param thread_data The data setup in the call to ThreadInit
     *
     * \retval 0 on success, -1 on failure
     */
    int (*Write)(const char *buffer, int buffer_len, void *init_data, void *thread_data);

    /**
     * \brief Final call to deinitialize this filetype.
     *
     * Called, usually on exit to deinitialize and free any resources
     * allocated during Init.
     *
     * \param init_data Data setup in the call to Init.
     */
    void (*Deinit)(void *init_data);

    /**
     * \brief Initiaize thread specific data.
     *
     * Initialize any thread specific data. For example, if
     * implementing a file output you might open the files here, so
     * you have one output file per thread.
     *
     * \param init_data Data setup during Init
     *
     * \param thread_id A unique ID to differentiate this thread from
     *     others. If EVE is not in threaded mode this will be called
     *     one with a ThreadId of 0. In threaded mode the ThreadId of
     *     0 correlates to the main Suricata thread.
     *
     * \param thread_data Output pointer for any data required by this
     *     thread.
     *
     * \retval 0 on success, -1 on failure
     */
    int (*ThreadInit)(void *init_data, ThreadId thread_id, void **thread_data);

    /**
     * \brief Called to deinitialize each thread.
     *
     * This function will be called for each thread. It is where any
     * resources allocated in ThreadInit should be released.
     *
     * \param init_data The data setup in Init
     *
     * \param thread_data The data setup in ThreadInit
     *
     * \retval 0 on success, -1 on failure
     */
    int (*ThreadDeinit)(void *init_data, void *thread_data);

    /* Internal list management. */
    TAILQ_ENTRY(SCEveFileType_) entries;
} SCEveFileType;

bool SCRegisterEveFileType(SCEveFileType *);

SCEveFileType *SCEveFindFileType(const char *name);

#endif
