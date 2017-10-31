/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * File based pcap packet acquisition support
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "source-pcap-file.h"
#include "util-time.h"
#include "util-debug.h"
#include "conf.h"
#include "util-error.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "tm-threads.h"
#include "util-optimize.h"
#include "flow-manager.h"
#include "util-profiling.h"
#include "runmode-unix-socket.h"
#include "util-checksum.h"
#include "util-atomic.h"

//directory support
#include <dirent.h> // dirent
#include <limits.h> // PATH_MAX
#include <sys/types.h>  // stat
#include <sys/stat.h>   // stat
#include <unistd.h>     // stat
#include "util-buffer.h"

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

extern int max_pending_packets;

typedef struct PcapFileGlobalVars_ {
    uint64_t cnt; /** packet counter */
    ChecksumValidationMode conf_checksum_mode;
    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, invalid_checksums);
} PcapFileGlobalVars;

typedef struct PcapFileSharedVars_
{
    char *bpf_string;

    uint32_t tenant_id;

    time_t last_processed;

    ThreadVars *tv;
    TmSlot *slot;

    /* counters */
    uint64_t pkts;
    uint64_t bytes;
    uint64_t files;

    uint8_t done;
    uint32_t errs;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;
} PcapFileSharedVars;

typedef struct PcapFileFileVars_
{
    char *filename;
    pcap_t *pcap_handle;

    int datalink;
    struct bpf_program filter;

    PcapFileSharedVars *shared;
} PcapFileFileVars;

typedef struct PcapFileDirectoryVars_
{
    char *filename;
    DIR *directory;
    PcapFileFileVars *current_file;
    time_t delay;
    time_t poll_interval;

    PcapFileSharedVars *shared;
} PcapFileDirectoryVars;

typedef union PcapFileBehaviorVar_
{
    PcapFileDirectoryVars *directory;
    PcapFileFileVars *file;
} PcapFileBehaviorVar;

typedef struct PcapFileThreadVars_
{
    PcapFileBehaviorVar behavior;
    int is_directory;

    PcapFileSharedVars shared;
} PcapFileThreadVars;

static PcapFileGlobalVars pcap_g;

TmEcode ReceivePcapFileLoop(ThreadVars *, void *, void *);
TmEcode ReceivePcapFileFileLoop(PcapFileThreadVars *tv, PcapFileFileVars *ptv);
TmEcode ReceivePcapFileDirectoryLoop(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);

TmEcode ReceivePcapFileThreadInit(ThreadVars *, const void *, void **);
void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapFile(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodePcapFileThreadInit(ThreadVars *, const void *, void **);
TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data);

TmEcode InitPcapFile(PcapFileFileVars *pfv, const char *filename);
TmEcode PcapRunStatus(PcapFileDirectoryVars *);
void CleanupPcapFileDirectoryVars(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);
void CleanupPcapFileFileVars(PcapFileThreadVars *tv, PcapFileFileVars *ptv);
void CleanupPcapFileThreadVars(PcapFileThreadVars *tv);
TmEcode PcapDirectoryFailure(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);
TmEcode PcapDirectoryDone(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);
TmEcode PcapCheckFile(char *filename, DIR **directory);
int PcapDirectoryGetModifiedTime(char const * file, time_t * out);
int PcapDirectorySortByStatTime(const void * vleft, const void * vright);
void FreeDirectoryMemBuffer(MemBuffer * buffer);
TmEcode PcapDirectoryPopulateBuffer(PcapFileDirectoryVars *ptv, time_t newer_than, time_t older_than, time_t *first_new_file_time, MemBuffer **directory_content);
TmEcode PcapDirectoryDispatch(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv, time_t *newer_than, time_t *older_than, time_t * first_new_file_time);

/**
 * Pcap Folder Utilities
 */
TmEcode PcapRunStatus(PcapFileDirectoryVars *ptv)
{
    if(RunModeUnixSocketIsActive()) {
        if( (suricata_ctl_flags & SURICATA_STOP) || UnixSocketPcapFile(TM_ECODE_OK, ptv->shared->last_processed) != TM_ECODE_OK ) {
            SCReturnInt(TM_ECODE_DONE);
        }
    } else {
        if(suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_DONE);
        }
    }
    SCReturnInt(TM_ECODE_OK);
}

void CleanupPcapFileFileVars(PcapFileThreadVars *tv, PcapFileFileVars *pfv)
{
    if(pfv->pcap_handle != NULL) {
        pcap_close(pfv->pcap_handle);
        pfv->pcap_handle = NULL;
    }
    if(pfv->filename != NULL) {
        SCFree(pfv->filename);
        pfv->filename = NULL;
    }
    if(tv->is_directory == 0) {
        tv->behavior.file = NULL;
    }
    pfv->shared = NULL;
    SCFree(pfv);
}

void CleanupPcapFileDirectoryVars(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    if(ptv->current_file != NULL) {
        CleanupPcapFileFileVars(tv, ptv->current_file);
        ptv->current_file = NULL;
    }
    closedir(ptv->directory);
    if(tv->is_directory == 1) {
        tv->behavior.directory = NULL;
    }
    if(ptv->filename != NULL) {
        SCFree(ptv->filename);
    }
    ptv->shared = NULL;
    SCFree(ptv);
}

void CleanupPcapFileThreadVars(PcapFileThreadVars *tv)
{
    if(tv->is_directory == 0) {
        if (tv->behavior.file != NULL) {
            CleanupPcapFileFileVars(tv, tv->behavior.file);
        }
        tv->behavior.file = NULL;
    } else {
        if(tv->behavior.directory != NULL) {
            CleanupPcapFileDirectoryVars(tv, tv->behavior.directory);
        }
        tv->behavior.directory = NULL;
    }
    if(tv->shared.bpf_string != NULL) {
        SCFree(tv->shared.bpf_string);
        tv->shared.bpf_string = NULL;
    }
    SCFree(tv);
}

TmEcode PcapDirectoryFailure(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_FAILED;

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, ptv->shared->last_processed);
    }

    CleanupPcapFileDirectoryVars(tv, ptv);

    SCReturnInt(status);
}

TmEcode PcapDirectoryDone(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_DONE;

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, ptv->shared->last_processed);
    }

    CleanupPcapFileDirectoryVars(tv, ptv);

    SCReturnInt(status);
}

TmEcode PcapCheckFile(char *filename, DIR **directory)
{
    DIR *temp_dir = NULL;
    TmEcode return_code = TM_ECODE_FAILED;

    temp_dir = opendir(filename);

    if (temp_dir == NULL)
    {
        switch (errno)
        {
            case EACCES:
                SCLogError(SC_ERR_FOPEN, "%s: Permission denied", filename);
                break;

            case EBADF:
                SCLogError(SC_ERR_FOPEN, "%s: Not a valid file descriptor opened for reading", filename);
                break;

            case EMFILE:
                SCLogError(SC_ERR_FOPEN, "%s: The per-process limit on the number of open file descriptors has been reached", filename);
                break;

            case ENFILE:
                SCLogError(SC_ERR_FOPEN, "%s: The system-wide limit on the number of open file descriptors has been reached", filename);
                break;

            case ENOENT:
                SCLogError(SC_ERR_FOPEN, "%s: Does not exist, or name is an empty string", filename);
                break;
            case ENOMEM:
                SCLogError(SC_ERR_FOPEN, "%s: Insufficient memory to complete the operation", filename);
                break;

            case ENOTDIR:
                SCLogInfo("%s: File is not a directory", filename);
                return_code = TM_ECODE_OK;
                break;

            default:
                SCLogError(SC_ERR_FOPEN, "%s: %" PRId32, filename, errno);
        }
    } else {
        *directory = temp_dir;
        return_code = TM_ECODE_OK;
    }

    return return_code;
}

int PcapDirectoryGetModifiedTime(char const * file, time_t * out)
{
    struct stat buf;
    int ret;

    if (file == NULL)
        return -1;

    if ((ret = stat(file, &buf)) != 0)
        return ret;

    *out = buf.st_mtime;

    return ret;
}

int PcapDirectorySortByStatTime(const void * vleft, const void * vright)
{
    if (vleft == vright)
        return 0;

    time_t leftTime = 0, rightTime = 0;

    int leftRet, rightRet;

    leftRet = PcapDirectoryGetModifiedTime(*(const char **)vleft, &leftTime);
    rightRet = PcapDirectoryGetModifiedTime(*(const char **)vright, &rightTime);

    if (leftRet == 0 && rightRet == 0)
    {
        return (leftTime == rightTime) ? 0 : ((leftTime < rightTime) ? -1 : 1);
    }
    else
    {
        return (leftRet == rightRet) ? 0 : ((leftRet < rightRet) ? -1 : 1);
    }
}

void FreeDirectoryMemBuffer(MemBuffer * buffer)
{
    if (buffer == NULL)
        return;

    size_t offset = 0;
    char *buffer_value;

    while (offset < MEMBUFFER_OFFSET(buffer))
    {
        buffer_value = *((char**)(MEMBUFFER_BUFFER(buffer) + offset));
        if(buffer_value != NULL) {
            SCFree(buffer_value);
        }
        offset += sizeof(char*);
    }
    MemBufferFree(buffer);
}

TmEcode PcapDirectoryPopulateBuffer(
        PcapFileDirectoryVars *ptv,
        time_t newer_than,
        time_t older_than,
        time_t *first_new_file_time,
        MemBuffer **directory_content
) {
    struct dirent * dir = NULL;

    MemBuffer *temp_directory_content = NULL;

    time_t fnt = *first_new_file_time;

    while ((dir = readdir(ptv->directory)) != NULL)
    {
        if (dir->d_type != DT_REG)
        {
            continue;
        }

        char pathbuff[PATH_MAX] = {0};

        int written = 0;

        written = snprintf(pathbuff, PATH_MAX, "%s/%s", ptv->filename, dir->d_name);

        if (written > 0 && written < PATH_MAX)
        {
            time_t temp_time = 0;

            if (PcapDirectoryGetModifiedTime(pathbuff, &temp_time) == 0)
            {
                SCLogDebug("File %s time (%lu > %lu < %lu)", pathbuff, newer_than, temp_time, older_than);

                // Skip files outside of our time range
                if (temp_time < newer_than) {
                    SCLogDebug("Skipping old file %s", pathbuff);
                    continue;
                }
                else if (temp_time > older_than) {
                    SCLogDebug("Skipping new file %s", pathbuff);
                    if (temp_time < fnt || fnt == 0)
                    {
                        *first_new_file_time = temp_time;
                    }
                    continue;
                }
            }

            if (temp_directory_content == NULL)
            {
                temp_directory_content = MemBufferCreateNew(sizeof(char*) * 32);
                if (!temp_directory_content)
                {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to create buffer");

                    SCReturnInt(TM_ECODE_FAILED);
                }
            }
            else if (MEMBUFFER_SIZE(temp_directory_content) - MEMBUFFER_OFFSET(temp_directory_content) < sizeof(char*))
            {
                // Double size
                if (!MemBufferExpand(&temp_directory_content, MEMBUFFER_SIZE(temp_directory_content)))
                {
                    FreeDirectoryMemBuffer(temp_directory_content);

                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to expand buffer");

                    SCReturnInt(TM_ECODE_FAILED);
                }
            }

            char * mem = SCMalloc(sizeof(char *) * (written + 1));
            if (!mem)
            {
                FreeDirectoryMemBuffer(temp_directory_content);

                SCLogError(SC_ERR_MEM_ALLOC, "Failed to copy file name");

                SCReturn(TM_ECODE_FAILED);
            }
            memcpy(mem, pathbuff, written + 1);

            SCLogDebug("Found \"%s\"", mem);

            *((char**)(MEMBUFFER_BUFFER(temp_directory_content) + MEMBUFFER_OFFSET(temp_directory_content))) = mem;

            MEMBUFFER_OFFSET(temp_directory_content) += sizeof(char *);
        }
        else
        {
            FreeDirectoryMemBuffer(temp_directory_content);

            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    if (temp_directory_content != NULL)
    {
        // Sort buffer
        qsort(MEMBUFFER_BUFFER(temp_directory_content), MEMBUFFER_OFFSET(temp_directory_content) / sizeof(char*), sizeof(char*), &PcapDirectorySortByStatTime);
    }

    *directory_content = temp_directory_content;

    SCReturn(TM_ECODE_OK);
}

/**
 * Pcap File Functionality
 */
void TmModuleReceivePcapFileRegister (void)
{
    tmm_modules[TMM_RECEIVEPCAPFILE].name = "ReceivePcapFile";
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadInit = ReceivePcapFileThreadInit;
    tmm_modules[TMM_RECEIVEPCAPFILE].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].PktAcqLoop = ReceivePcapFileLoop;
    tmm_modules[TMM_RECEIVEPCAPFILE].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadExitPrintStats = ReceivePcapFileThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPFILE].ThreadDeinit = ReceivePcapFileThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAPFILE].cap_flags = 0;
    tmm_modules[TMM_RECEIVEPCAPFILE].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePcapFileRegister (void)
{
    tmm_modules[TMM_DECODEPCAPFILE].name = "DecodePcapFile";
    tmm_modules[TMM_DECODEPCAPFILE].ThreadInit = DecodePcapFileThreadInit;
    tmm_modules[TMM_DECODEPCAPFILE].Func = DecodePcapFile;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].ThreadDeinit = DecodePcapFileThreadDeinit;
    tmm_modules[TMM_DECODEPCAPFILE].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAPFILE].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAPFILE].flags = TM_FLAG_DECODE_TM;
}

void PcapFileGlobalInit()
{
    memset(&pcap_g, 0x00, sizeof(pcap_g));
    SC_ATOMIC_INIT(pcap_g.invalid_checksums);
}

static void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();

    PcapFileFileVars *ptv = (PcapFileFileVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }
    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFILE);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = ptv->datalink;
    p->pcap_cnt = ++pcap_g.cnt;

    p->pcap_v.tenant_id = ptv->shared->tenant_id;
    ptv->shared->pkts++;
    ptv->shared->bytes += h->caplen;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->shared->tv, p);
        PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);
        SCReturn;
    }

    /* We only check for checksum disable */
    if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->shared->pkts, p->pcap_cnt,
                                  SC_ATOMIC_GET(pcap_g.invalid_checksums))) {
            pcap_g.checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);

    if (TmThreadsSlotProcessPkt(ptv->shared->tv, ptv->shared->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(ptv->pcap_handle);
        ptv->shared->cb_result = TM_ECODE_FAILED;
    }

    SCReturn;
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode ReceivePcapFileFileLoop(PcapFileThreadVars *tv, PcapFileFileVars *ptv)
{
    SCEnter();

    int packet_q_len = 64;
    int r;
    TmEcode loop_result = TM_ECODE_OK;

    while (loop_result == TM_ECODE_OK) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Right now we just support reading packets one at a time. */
        r = pcap_dispatch(ptv->pcap_handle, packet_q_len,
                          (pcap_handler)PcapFileCallbackLoop, (u_char *)ptv);
        if (unlikely(r == -1)) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                       r, pcap_geterr(ptv->pcap_handle));
            if (ptv->shared->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            loop_result = TM_ECODE_DONE;
        } else if (unlikely(r == 0)) {
            SCLogInfo("pcap file end of file reached (pcap err code %" PRId32 ")", r);
            tv->shared.files++;
            loop_result = TM_ECODE_DONE;
        } else if (ptv->shared->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH, "Pcap callback PcapFileCallbackLoop failed");
            loop_result = TM_ECODE_FAILED;
        }
        StatsSyncCountersIfSignalled(ptv->shared->tv);
    }

    SCReturnInt(loop_result);
}

TmEcode InitPcapFile(PcapFileFileVars *pfv, const char *filename)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    pfv->filename = SCStrdup(filename);
    if (unlikely(pfv->filename == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate filename");
        SCReturnInt(TM_ECODE_FAILED);
    }
    pfv->pcap_handle = pcap_open_offline(pfv->filename, errbuf);
    if (pfv->pcap_handle == NULL) {
        SCLogError(SC_ERR_FOPEN, "%s", errbuf);
        if (!RunModeUnixSocketIsActive()) {
            SCReturnInt(TM_ECODE_FAILED);
        } else {
            UnixSocketPcapFile(TM_ECODE_FAILED, 0);
            SCReturnInt(TM_ECODE_DONE);
        }
    }

    if(pfv->shared != NULL && pfv->shared->bpf_string != NULL) {
        SCLogInfo("using bpf-filter \"%s\"", pfv->shared->bpf_string);

        if (pcap_compile(pfv->pcap_handle, &pfv->filter, pfv->shared->bpf_string, 1, 0) < 0) {
            SCLogError(SC_ERR_BPF,"bpf compilation error %s",
                       pcap_geterr(pfv->pcap_handle));
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (pcap_setfilter(pfv->pcap_handle, &pfv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s", pcap_geterr(pfv->pcap_handle));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    pfv->datalink = pcap_datalink(pfv->pcap_handle);
    SCLogDebug("datalink %" PRId32 "", pfv->datalink);

    switch (pfv->datalink) {
        case LINKTYPE_LINUX_SLL:
        case LINKTYPE_ETHERNET:
        case LINKTYPE_PPP:
        case LINKTYPE_RAW:
        case LINKTYPE_RAW2:
        case LINKTYPE_NULL:
            break;

        default:
            SCLogError(SC_ERR_UNIMPLEMENTED, "datalink type %" PRId32 " not "
                    "(yet) supported in module PcapFile.", pfv->datalink);
            if (! RunModeUnixSocketIsActive()) {
                SCReturnInt(TM_ECODE_FAILED);
            } else {
                UnixSocketPcapFile(TM_ECODE_DONE, 0);
                SCReturnInt(TM_ECODE_DONE);
            }
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode PcapDirectoryDispatch(
        PcapFileThreadVars *tv,
        PcapFileDirectoryVars *pv,
        time_t *newer_than,
        time_t *older_than,
        time_t * first_new_file_time
)
{
    MemBuffer *directory_content = NULL;

    if(PcapDirectoryPopulateBuffer(pv, *newer_than, *older_than, first_new_file_time, &directory_content) == TM_ECODE_FAILED) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    TmEcode status = TM_ECODE_OK;

    if(directory_content == NULL) {
        *older_than = time(NULL) - pv->delay;
        SCLogInfo("Directory %s has no files to process", pv->filename);
        rewinddir(pv->directory);
        status = TM_ECODE_OK;
    } else {
        size_t offset = 0;

        while (status == TM_ECODE_OK && offset < MEMBUFFER_OFFSET(directory_content)) {
            char *pathbuff = (*((char **) (MEMBUFFER_BUFFER(directory_content) + offset)));

            if(pathbuff != NULL) {

                SCLogDebug("Processing file %s", pathbuff);

                PcapFileFileVars *pftv = SCMalloc(sizeof(PcapFileFileVars));
                if (unlikely(pftv == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate PcapFileFileVars");
                    SCReturnInt(TM_ECODE_FAILED);
                }
                memset(pftv, 0, sizeof(PcapFileFileVars));

                pftv->shared = pv->shared;

                if (InitPcapFile(pftv, pathbuff) == TM_ECODE_FAILED) {
                    FreeDirectoryMemBuffer(directory_content);
                    CleanupPcapFileFileVars(tv, pftv);
                    SCReturnInt(TM_ECODE_FAILED);
                }

                pv->current_file = pftv;

                if (ReceivePcapFileFileLoop(tv, pftv) == TM_ECODE_FAILED) {
                    FreeDirectoryMemBuffer(directory_content);
                    CleanupPcapFileFileVars(tv, pftv);
                    SCReturnInt(TM_ECODE_FAILED);
                }

                CleanupPcapFileFileVars(tv, pftv);
                pv->current_file = NULL;

                time_t temp_time;

                if (PcapDirectoryGetModifiedTime(pathbuff, &temp_time) != 0) {
                    temp_time = *newer_than;
                }
                SCLogDebug("Processed file %s, processed up to %ld", pathbuff, temp_time);
                pv->shared->last_processed = temp_time;

                status = PcapRunStatus(pv);
            }
            offset += sizeof(char *);
        }

        *newer_than = *older_than;
    }
    FreeDirectoryMemBuffer(directory_content);
    *older_than = time(NULL) - pv->delay;

    SCReturnInt(status);
}

TmEcode ReceivePcapFileDirectoryLoop(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    SCEnter();

    time_t newer_than = 0;
    time_t older_than = time(NULL) - ptv->delay;
    uint32_t poll_seconds = (uint32_t)localtime(&ptv->poll_interval)->tm_sec;

    TmEcode status = TM_ECODE_OK;

    while (status == TM_ECODE_OK) {
        if (ptv->directory != NULL) {
            SCLogInfo("Pcap File Ok, Looping");
            //loop while directory is ok
            while (status == TM_ECODE_OK) {
                SCLogInfo("Processing pcaps directory %s, files must be newer than %ld and older than %ld",
                          ptv->filename, newer_than, older_than);
                time_t first_new_file_time;
                status = PcapDirectoryDispatch(tv, ptv, &newer_than, &older_than, &first_new_file_time);
                if (status == TM_ECODE_OK) {
                    sleep(poll_seconds);
                    //update our status based on suricata control flags or unix command socket
                    status = PcapRunStatus(ptv);
                }
            }

            //check directory
            if(PcapCheckFile(ptv->filename, &(ptv->directory)) == TM_ECODE_FAILED) {
                SCLogInfo("Directory %s no longer exists, stopping", ptv->filename);
                status = TM_ECODE_DONE;
            }
        } else {
            status = TM_ECODE_DONE;
        }
    }

    StatsSyncCountersIfSignalled(ptv->shared->tv);

    if(status == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_PCAP_DISPATCH, "Directory run mode failed");
        status = PcapDirectoryFailure(tv, ptv);
    } else {
        SCLogInfo("Directory run mode complete");
        status = PcapDirectoryDone(tv, ptv);
    }

    SCReturnInt(status);
}

TmEcode ReceivePcapFileLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    TmEcode status = TM_ECODE_OK;
    PcapFileThreadVars *ptv = (PcapFileThreadVars *) data;
    TmSlot *s = (TmSlot *)slot;

    ptv->shared.slot = s->slot_next;
    ptv->shared.cb_result = TM_ECODE_OK;

    if(ptv->is_directory == 0) {
        SCLogInfo("Starting file run for %s", ptv->behavior.file->filename);
        status = ReceivePcapFileFileLoop(ptv, ptv->behavior.file);
        if (! RunModeUnixSocketIsActive()) {
            EngineStop();
        } else {
            status = UnixSocketPcapFile(status, ptv->shared.last_processed);
        }
        CleanupPcapFileFileVars(ptv, ptv->behavior.file);
    } else {
        SCLogInfo("Starting directory run for %s", ptv->behavior.directory->filename);
        status = ReceivePcapFileDirectoryLoop(ptv, ptv->behavior.directory);
    }

    SCReturnInt(status);
}

TmEcode ReceivePcapFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    const char *tmpstring = NULL;
    const char *tmp_bpf_string = NULL;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    PcapFileThreadVars *ptv = SCMalloc(sizeof(PcapFileThreadVars));
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PcapFileThreadVars));

    intmax_t tenant = 0;
    if (ConfGetInt("pcap-file.tenant-id", &tenant) == 1) {
        if (tenant > 0 && tenant < UINT_MAX) {
            ptv->shared.tenant_id = (uint32_t)tenant;
            SCLogInfo("tenant %u", ptv->shared.tenant_id);
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant out of range");
        }
    }

    if (ConfGet("bpf-filter", &(tmp_bpf_string)) != 1) {
        SCLogDebug("could not get bpf or none specified");
    } else {
        ptv->shared.bpf_string = SCStrdup(tmp_bpf_string);
        if (unlikely(ptv->shared.bpf_string == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate bpf_string");
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    DIR *directory = NULL;
    SCLogInfo("Checking file or directory %s", (char*)initdata);
    if(PcapCheckFile((char *)initdata, &directory) == TM_ECODE_FAILED) {
        CleanupPcapFileThreadVars(ptv);
        SCReturnInt(TM_ECODE_FAILED);
    }

    if(directory == NULL) {
        SCLogInfo("Argument %s was a file", (char *)initdata);
        PcapFileFileVars *pv = SCMalloc(sizeof(PcapFileFileVars));
        if (unlikely(pv == NULL))
            SCReturnInt(TM_ECODE_FAILED);
        memset(pv, 0, sizeof(PcapFileFileVars));

        TmEcode init_file_return = InitPcapFile(pv, (char *)initdata);
        if(init_file_return == TM_ECODE_OK) {
            pv->shared = &ptv->shared;

            ptv->is_directory = 0;
            ptv->behavior.file = pv;
        } else {
            CleanupPcapFileFileVars(ptv, pv);
            SCReturnInt(init_file_return);
        }
    } else {
        SCLogInfo("Argument %s was a directory", (char *)initdata);
        PcapFileDirectoryVars *pv = SCMalloc(sizeof(PcapFileDirectoryVars));
        if (unlikely(pv == NULL))
            SCReturnInt(TM_ECODE_FAILED);
        memset(pv, 0, sizeof(PcapFileDirectoryVars));

        pv->delay = 30;
        intmax_t delay = 0;
        if (ConfGetInt("pcap-file.delay", &delay) == 1) {
            if (delay > 0 && delay < UINT_MAX) {
                pv->delay = (time_t)delay;
                SCLogDebug("delay %u", pv->delay);
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "delay out of range");
            }
        }

        pv->poll_interval = 5;
        intmax_t poll_interval = 0;
        if (ConfGetInt("pcap-file.poll-interval", &poll_interval) == 1) {
            if (poll_interval > 0 && poll_interval < UINT_MAX) {
                pv->poll_interval = (time_t)poll_interval;
                SCLogDebug("poll-interval %u", pv->delay);
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "poll-interval out of range");
            }
        }

        pv->shared = &ptv->shared;
        pv->filename = SCStrdup((char*)initdata);
        if (unlikely(pv->filename == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate filename");
            SCReturnInt(TM_ECODE_FAILED);
        }
        pv->directory = directory;

        ptv->is_directory = 1;
        ptv->behavior.directory = pv;
    }

    if (ConfGet("pcap-file.checksum-checks", &tmpstring) != 1) {
        pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_AUTO;
    } else {
        if (strcmp(tmpstring, "auto") == 0) {
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpstring)){
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpstring)) {
            pcap_g.conf_checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        }
    }
    pcap_g.checksum_mode = pcap_g.conf_checksum_mode;

    ptv->shared.tv = tv;
    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

void ReceivePcapFileThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;

    if (pcap_g.conf_checksum_mode == CHECKSUM_VALIDATION_AUTO &&
        pcap_g.cnt < CHECKSUM_SAMPLE_COUNT &&
        SC_ATOMIC_GET(pcap_g.invalid_checksums)) {
        uint64_t chrate = pcap_g.cnt / SC_ATOMIC_GET(pcap_g.invalid_checksums);
        if (chrate < CHECKSUM_INVALID_RATIO)
            SCLogWarning(SC_ERR_INVALID_CHECKSUM,
                         "1/%" PRIu64 "th of packets have an invalid checksum,"
                                 " consider setting pcap-file.checksum-checks variable to no"
                                 " or use '-k none' option on command line.",
                         chrate);
        else
            SCLogInfo("1/%" PRIu64 "th of packets have an invalid checksum",
                      chrate);
    }
    SCLogNotice(
            "Pcap-file module read %" PRIu64 " files, %" PRIu64 " packets, %" PRIu64 " bytes",
            ptv->shared.files,
            ptv->shared.pkts,
            ptv->shared.bytes
    );
}

TmEcode ReceivePcapFileThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFileThreadVars *ptv = (PcapFileThreadVars *)data;
    if (ptv != NULL) {
        CleanupPcapFileThreadVars(ptv);
    }
    SCReturnInt(TM_ECODE_OK);
}

static double prev_signaled_ts = 0;

TmEcode DecodePcapFile(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    int (*decoder)(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);

    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    /* XXX HACK: flow timeout can call us for injected pseudo packets
     *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
    if (p->flags & PKT_PSEUDO_STREAM_END)
        return TM_ECODE_OK;

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    double curr_ts = p->ts.tv_sec + p->ts.tv_usec / 1000.0;
    if (curr_ts < prev_signaled_ts || (curr_ts - prev_signaled_ts) > 60.0) {
        prev_signaled_ts = curr_ts;
        FlowWakeupFlowManagerThread();
    }

    switch (p->datalink) {
        case LINKTYPE_LINUX_SLL:
            decoder = DecodeSll;
            break;
        case LINKTYPE_ETHERNET:
            decoder = DecodeEthernet;
            break;
        case LINKTYPE_PPP:
            decoder = DecodePPP;
            break;
        case LINKTYPE_RAW:
        case LINKTYPE_RAW2:
            decoder = DecodeRaw;
            break;
        case LINKTYPE_NULL:
            decoder = DecodeNull;
            break;

        default:
            SCLogError(SC_ERR_UNIMPLEMENTED, "datalink type %" PRId32 " not "
                    "(yet) supported in module PcapFile.", p->datalink);
            SCReturnInt(TM_ECODE_FAILED);
    }

    /* call the decoder */
    decoder(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

#ifdef DEBUG
    BUG_ON(p->pkt_src != PKT_SRC_WIRE && p->pkt_src != PKT_SRC_FFR);
#endif

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

#ifdef __SC_CUDA_SUPPORT__
    if (CudaThreadVarsInit(&dtv->cuda_vars) < 0)
        SCReturnInt(TM_ECODE_FAILED);
#endif

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

void PcapIncreaseInvalidChecksum()
{
    (void) SC_ATOMIC_ADD(pcap_g.invalid_checksums, 1);
}

/* eof */
