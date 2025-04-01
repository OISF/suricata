/* Copyright (C) 2020-2024 Open Information Security Foundation
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
#include "suricata-plugin.h"
#include "output-eve.h"
#include "util-mem.h"
#include "util-debug.h"

#define FILETYPE_NAME "json-filetype-plugin"

/**
 * Per thread context data for each logging thread.
 */
typedef struct ThreadData_ {
    /** The thread ID, for demonstration purposes only. */
    ThreadId thread_id;

    /** The number of records logged on this thread. */
    uint64_t count;
} ThreadData;

/**
 * A context object for each eve logger using this output.
 */
typedef struct Context_ {
    /** Verbose, or print to stdout. */
    int verbose;
} Context;

/**
 * This function is called to initialize the output, it can be somewhat thought
 * of like opening a file.
 *
 * \param conf The EVE configuration node using this output.
 *
 * \param threaded If true the EVE subsystem is running in threaded mode.
 *
 * \param data A pointer where context data can be stored relevant to this
 *      output.
 *
 * Eve output plugins need to be thread aware as the threading happens
 * at a lower level than the EVE output, so a flag is provided here to
 * notify the plugin if threading is enabled or not.
 *
 * If the plugin does not work with threads disabled, or enabled, this function
 * should return -1.
 *
 * Note for upgrading a plugin from 6.0 to 7.0: The ConfNode in 7.0 is the
 * configuration for the eve instance, not just a node named after the plugin.
 * This allows the plugin to get more context about what it is logging.
 */
static int FiletypeInit(const SCConfNode *conf, const bool threaded, void **data)
{
    SCLogNotice("Initializing template eve output plugin: threaded=%d", threaded);
    Context *context = SCCalloc(1, sizeof(Context));
    if (context == NULL) {
        return -1;
    }

    /* Verbose by default. */
    int verbose = 1;

    /* An example of how you can access configuration data from a
     * plugin. */
    if (conf && (conf = SCConfNodeLookupChild(conf, "eve-template")) != NULL) {
        if (!SCConfGetChildValueBool(conf, "verbose", &verbose)) {
            verbose = 1;
        } else {
            SCLogNotice("Read verbose configuration value of %d", verbose);
        }
    }
    context->verbose = verbose;

    *data = context;
    return 0;
}

/**
 * This function is called when the output is closed.
 *
 * This will be called after ThreadDeinit is called for each thread.
 *
 * \param data The data allocated in FiletypeInit. It should be cleaned up and
 *      deallocated here.
 */
static void FiletypeDeinit(void *data)
{
    SCLogNotice("data=%p", data);
    Context *ctx = data;
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

/**
 * Initialize per thread context.
 *
 * \param ctx The context created in TemplateInitOutput.
 *
 * \param thread_id An identifier for this thread.
 *
 * \param thread_data Pointer where thread specific context can be stored.
 *
 * When the EVE output is running in threaded mode this will be called once for
 * each output thread with a unique thread_id. For regular file logging in
 * threaded mode Suricata uses the thread_id to construct the files in the form
 * of "eve.<thread_id>.json". This plugin may want to do similar, or open
 * multiple connections to whatever the final logging location might be.
 *
 * In the case of non-threaded EVE logging this function is called
 * once with a thread_id of 0.
 */
static int FiletypeThreadInit(const void *ctx, const ThreadId thread_id, void **thread_data)
{
    SCLogNotice("thread_id=%d", thread_id);
    ThreadData *tdata = SCCalloc(1, sizeof(ThreadData));
    if (tdata == NULL) {
        SCLogError("Failed to allocate thread data");
        return -1;
    }
    tdata->thread_id = thread_id;
    *thread_data = tdata;
    SCLogNotice(
            "Initialized thread %03d (pthread_id=%" PRIuMAX ")", tdata->thread_id, pthread_self());
    return 0;
}

/**
 * Deinitialize a thread.
 *
 * This is where any cleanup per thread should be done including free'ing of the
 * thread_data if needed.
 */
static void FiletypeThreadDeinit(const void *ctx, void *thread_data)
{
    SCLogNotice("thread_data=%p", thread_data);
    if (thread_data == NULL) {
        // Nothing to do.
        return;
    }

    ThreadData *tdata = thread_data;
    SCLogNotice(
            "Deinitializing thread %d: records written: %" PRIu64, tdata->thread_id, tdata->count);
    SCFree(tdata);
}

/**
 * This method is called with formatted Eve JSON data.
 *
 * \param buffer Formatted JSON buffer \param buffer_len Length of formatted
 * JSON buffer \param data Data set in Init callback \param thread_data Data set
 * in ThreadInit callbacl
 *
 * Do not block in this thread, it will cause packet loss. Instead of outputting
 * to any resource that may block it might be best to enqueue the buffers for
 * further processing which will require copying of the provided buffer.
 */
static int FiletypeWrite(
        const char *buffer, const int buffer_len, const void *data, void *thread_data)
{
    const Context *ctx = data;
    ThreadData *thread = thread_data;

    SCLogNotice("thread_id=%d, data=%p, thread_data=%p", thread->thread_id, data, thread_data);

    thread->count++;

    if (ctx->verbose) {
        SCLogNotice("Received write with thread_data %p: %s", thread_data, buffer);
    }
    return 0;
}

/**
 * Called by Suricata to initialize the module. This module registers
 * new file type to the JSON logger.
 */
void PluginInit(void)
{
    SCEveFileType *my_output = SCCalloc(1, sizeof(SCEveFileType));
    my_output->name = FILETYPE_NAME;
    my_output->Init = FiletypeInit;
    my_output->Deinit = FiletypeDeinit;
    my_output->ThreadInit = FiletypeThreadInit;
    my_output->ThreadDeinit = FiletypeThreadDeinit;
    my_output->Write = FiletypeWrite;
    if (!SCRegisterEveFileType(my_output)) {
        FatalError("Failed to register filetype plugin: %s", FILETYPE_NAME);
    }
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = FILETYPE_NAME,
    .plugin_version = "0.1.0",
    .author = "FirstName LastName <name@example.org>",
    .license = "GPL-2.0-only",
    .Init = PluginInit,
};

/**
 * The function called by Suricata after loading this plugin.
 *
 * A pointer to a populated SCPlugin struct must be returned.
 */
const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
