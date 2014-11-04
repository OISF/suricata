/* Copyright (C) 2012 Open Information Security Foundation
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
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-pcap-file.h"
#include "log-httplog.h"
#include "output.h"
#include "source-pfring.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "unix-manager.h"

#include "flow-manager.h"
#include "flow-timeout.h"
#include "stream-tcp.h"
#include "output.h"
#include "host.h"
#include "defrag.h"

static const char *default_mode = NULL;

int unix_socket_mode_is_running = 0;

typedef struct PcapFiles_ {
    char *filename;
    char *output_dir;
    TAILQ_ENTRY(PcapFiles_) next;
} PcapFiles;

typedef struct PcapCommand_ {
    DetectEngineCtx *de_ctx;
    TAILQ_HEAD(, PcapFiles_) files;
    int running;
    char *currentfile;
} PcapCommand;

const char *RunModeUnixSocketGetDefaultMode(void)
{
    return default_mode;
}

#ifdef BUILD_UNIX_SOCKET

static int unix_manager_file_task_running = 0;
static int unix_manager_file_task_failed = 0;

/**
 * \brief return list of files in the queue
 *
 * \retval 0 in case of error, 1 in case of success
 */
static TmEcode UnixSocketPcapFilesList(json_t *cmd, json_t* answer, void *data)
{
    PcapCommand *this = (PcapCommand *) data;
    int i = 0;
    PcapFiles *file;
    json_t *jdata;
    json_t *jarray;

    jdata = json_object();
    if (jdata == NULL) {
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }
    jarray = json_array();
    if (jarray == NULL) {
        json_decref(jdata);
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }
    TAILQ_FOREACH(file, &this->files, next) {
        json_array_append_new(jarray, json_string(file->filename));
        i++;
    }
    json_object_set_new(jdata, "count", json_integer(i));
    json_object_set_new(jdata, "files", jarray);
    json_object_set_new(answer, "message", jdata);
    return TM_ECODE_OK;
}

static TmEcode UnixSocketPcapFilesNumber(json_t *cmd, json_t* answer, void *data)
{
    PcapCommand *this = (PcapCommand *) data;
    int i = 0;
    PcapFiles *file;

    TAILQ_FOREACH(file, &this->files, next) {
        i++;
    }
    json_object_set_new(answer, "message", json_integer(i));
    return TM_ECODE_OK;
}

static TmEcode UnixSocketPcapCurrent(json_t *cmd, json_t* answer, void *data)
{
    PcapCommand *this = (PcapCommand *) data;

    if (this->currentfile) {
        json_object_set_new(answer, "message", json_string(this->currentfile));
    } else {
        json_object_set_new(answer, "message", json_string("None"));
    }
    return TM_ECODE_OK;
}



static void PcapFilesFree(PcapFiles *cfile)
{
    if (cfile == NULL)
        return;
    if (cfile->filename)
        SCFree(cfile->filename);
    if (cfile->output_dir)
        SCFree(cfile->output_dir);
    SCFree(cfile);
}

/**
 * \brief Add file to file queue
 *
 * \param this a UnixCommand:: structure
 * \param filename absolute filename
 * \param output_dir absolute name of directory where log will be put
 *
 * \retval 0 in case of error, 1 in case of success
 */
TmEcode UnixListAddFile(PcapCommand *this, const char *filename, const char *output_dir)
{
    PcapFiles *cfile = NULL;
    if (filename == NULL || this == NULL)
        return TM_ECODE_FAILED;
    cfile = SCMalloc(sizeof(PcapFiles));
    if (unlikely(cfile == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate new file");
        return TM_ECODE_FAILED;
    }
    memset(cfile, 0, sizeof(PcapFiles));

    cfile->filename = SCStrdup(filename);
    if (unlikely(cfile->filename == NULL)) {
        SCFree(cfile);
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup filename");
        return TM_ECODE_FAILED;
    }

    if (output_dir) {
        cfile->output_dir = SCStrdup(output_dir);
        if (unlikely(cfile->output_dir == NULL)) {
            SCFree(cfile->filename);
            SCFree(cfile);
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to dup output_dir");
            return TM_ECODE_FAILED;
        }
    }

    TAILQ_INSERT_TAIL(&this->files, cfile, next);
    return TM_ECODE_OK;
}

/**
 * \brief Command to add a file to treatment list
 *
 * \param cmd the content of command Arguments as a json_t object
 * \param answer the json_t object that has to be used to answer
 * \param data pointer to data defining the context here a PcapCommand::
 */
TmEcode UnixSocketAddPcapFile(json_t *cmd, json_t* answer, void *data)
{
    PcapCommand *this = (PcapCommand *) data;
    int ret;
    const char *filename;
    const char *output_dir;
#ifdef OS_WIN32
    struct _stat st;
#else
    struct stat st;
#endif /* OS_WIN32 */

    json_t *jarg = json_object_get(cmd, "filename");
    if(!json_is_string(jarg)) {
        SCLogInfo("error: command is not a string");
        json_object_set_new(answer, "message", json_string("command is not a string"));
        return TM_ECODE_FAILED;
    }
    filename = json_string_value(jarg);
#ifdef OS_WIN32
    if(_stat(filename, &st) != 0) {
#else
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        json_object_set_new(answer, "message", json_string("File does not exist"));
        return TM_ECODE_FAILED;
    }

    json_t *oarg = json_object_get(cmd, "output-dir");
    if (oarg != NULL) {
        if(!json_is_string(oarg)) {
            SCLogInfo("error: output dir is not a string");
            json_object_set_new(answer, "message", json_string("output dir is not a string"));
            return TM_ECODE_FAILED;
        }
        output_dir = json_string_value(oarg);
    } else {
        SCLogInfo("error: can't get output-dir");
        json_object_set_new(answer, "message", json_string("output dir param is mandatory"));
        return TM_ECODE_FAILED;
    }

#ifdef OS_WIN32
    if(_stat(output_dir, &st) != 0) {
#else
    if(stat(output_dir, &st) != 0) {
#endif /* OS_WIN32 */
        json_object_set_new(answer, "message", json_string("Output directory does not exist"));
        return TM_ECODE_FAILED;
    }

    ret = UnixListAddFile(this, filename, output_dir);
    switch(ret) {
        case TM_ECODE_FAILED:
            json_object_set_new(answer, "message", json_string("Unable to add file to list"));
            return TM_ECODE_FAILED;
        case TM_ECODE_OK:
            SCLogInfo("Added file '%s' to list", filename);
            json_object_set_new(answer, "message", json_string("Successfully added file to list"));
            return TM_ECODE_OK;
    }
    return TM_ECODE_OK;
}

/**
 * \brief Handle the file queue
 *
 * This function check if there is currently a file
 * being parse. If it is not the case, it will start to
 * work on a new file. This implies to start a new 'pcap-file'
 * running mode after having set the file and the output dir.
 * This function also handles the cleaning of the previous
 * running mode.
 *
 * \param this a UnixCommand:: structure
 * \retval 0 in case of error, 1 in case of success
 */
TmEcode UnixSocketPcapFilesCheck(void *data)
{
    PcapCommand *this = (PcapCommand *) data;
    if (unix_manager_file_task_running == 1) {
        return TM_ECODE_OK;
    }
    if ((unix_manager_file_task_failed == 1) || (this->running == 1)) {
        if (unix_manager_file_task_failed) {
            SCLogInfo("Preceeding task failed, cleaning the running mode");
        }
        unix_manager_file_task_failed = 0;
        this->running = 0;
        if (this->currentfile) {
            SCFree(this->currentfile);
        }
        this->currentfile = NULL;

        /* handle graceful shutdown of the flow engine, it's helper
         * threads and the packet threads */
        FlowKillFlowManagerThread();
        TmThreadDisableThreadsWithTMS(TM_FLAG_RECEIVE_TM | TM_FLAG_DECODE_TM);
        FlowForceReassembly();
        TmThreadKillThreadsFamily(TVT_PPT);
        TmThreadClearThreadsFamily(TVT_PPT);
        FlowKillFlowRecyclerThread();
        RunModeShutDown();

        /* kill remaining mgt threads */
        TmThreadKillThreadsFamily(TVT_MGMT);
        TmThreadClearThreadsFamily(TVT_MGMT);
        SCPerfReleaseResources();

        /* mgt and ppt threads killed, we can run non thread-safe
         * shutdown functions */
        FlowShutdown();
        HostCleanup();
        StreamTcpFreeConfig(STREAM_VERBOSE);
        DefragDestroy();
        TmqResetQueues();
    }
    if (!TAILQ_EMPTY(&this->files)) {
        PcapFiles *cfile = TAILQ_FIRST(&this->files);
        TAILQ_REMOVE(&this->files, cfile, next);
        SCLogInfo("Starting run for '%s'", cfile->filename);
        unix_manager_file_task_running = 1;
        this->running = 1;
        if (ConfSet("pcap-file.file", cfile->filename) != 1) {
            SCLogInfo("Can not set working file to '%s'", cfile->filename);
            PcapFilesFree(cfile);
            return TM_ECODE_FAILED;
        }
        if (cfile->output_dir) {
            if (ConfSet("default-log-dir", cfile->output_dir) != 1) {
                SCLogInfo("Can not set output dir to '%s'", cfile->output_dir);
                PcapFilesFree(cfile);
                return TM_ECODE_FAILED;
            }
        }
        this->currentfile = SCStrdup(cfile->filename);
        if (unlikely(this->currentfile == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed file name allocation");
            return TM_ECODE_FAILED;
        }
        PcapFilesFree(cfile);
        DefragInit();
        FlowInitConfig(FLOW_QUIET);
        StreamTcpInitConfig(STREAM_VERBOSE);
        RunModeInitializeOutputs();
        SCPerfInitCounterApi();
        RunModeDispatch(RUNMODE_PCAP_FILE, NULL, this->de_ctx);
        FlowManagerThreadSpawn();
        FlowRecyclerThreadSpawn();
        SCPerfSpawnThreads();
        /* Un-pause all the paused threads */
        TmThreadContinueThreads();
    }
    return TM_ECODE_OK;
}
#endif

void RunModeUnixSocketRegister(void)
{
#ifdef BUILD_UNIX_SOCKET
    RunModeRegisterNewRunMode(RUNMODE_UNIX_SOCKET, "single",
                              "Unix socket mode",
                              RunModeUnixSocketSingle);
    default_mode = "single";
#endif
    return;
}

void UnixSocketPcapFile(TmEcode tm)
{
#ifdef BUILD_UNIX_SOCKET
    switch (tm) {
        case TM_ECODE_DONE:
            unix_manager_file_task_running = 0;
            break;
        case TM_ECODE_FAILED:
            unix_manager_file_task_running = 0;
            unix_manager_file_task_failed = 1;
            break;
        case TM_ECODE_OK:
            break;
    }
#endif
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeUnixSocketSingle(DetectEngineCtx *de_ctx)
{
#ifdef BUILD_UNIX_SOCKET
    PcapCommand *pcapcmd = SCMalloc(sizeof(PcapCommand));

    if (unlikely(pcapcmd == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can not allocate pcap command");
        return 1;
    }
    pcapcmd->de_ctx = de_ctx;
    TAILQ_INIT(&pcapcmd->files);
    pcapcmd->running = 0;
    pcapcmd->currentfile = NULL;

    UnixManagerThreadSpawn(de_ctx, 1);

    unix_socket_mode_is_running = 1;

    UnixManagerRegisterCommand("pcap-file", UnixSocketAddPcapFile, pcapcmd, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("pcap-file-number", UnixSocketPcapFilesNumber, pcapcmd, 0);
    UnixManagerRegisterCommand("pcap-file-list", UnixSocketPcapFilesList, pcapcmd, 0);
    UnixManagerRegisterCommand("pcap-current", UnixSocketPcapCurrent, pcapcmd, 0);

    UnixManagerRegisterBackgroundTask(UnixSocketPcapFilesCheck, pcapcmd);
#endif

    return 0;
}

int RunModeUnixSocketIsActive(void)
{
    return unix_socket_mode_is_running;
}




