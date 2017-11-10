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
#include "queue.h"

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

/**
 * Data that is shared amongst File, Directory, and Thread level vars
 */
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

/**
 * Data specific to a single pcap file
 */
typedef struct PcapFileFileVars_
{
    char *filename;
    pcap_t *pcap_handle;

    int datalink;
    struct bpf_program filter;

    PcapFileSharedVars *shared;
} PcapFileFileVars;

typedef struct PendingFile_
{
    char *filename;
    TAILQ_ENTRY(PendingFile_) next;
} PendingFile;
/**
 * Data specific to a directory of pcap files
 */
typedef struct PcapFileDirectoryVars_
{
    char *filename;
    DIR *directory;
    PcapFileFileVars *current_file;
    bool should_loop;
    time_t delay;
    time_t poll_interval;

    TAILQ_HEAD(PendingFiles, PendingFile_) directory_content;

    PcapFileSharedVars *shared;
} PcapFileDirectoryVars;

/**
 * Union determining whether the behavior of the thread is file or directory
 */
typedef union PcapFileBehaviorVar_
{
    PcapFileDirectoryVars *directory;
    PcapFileFileVars *file;
} PcapFileBehaviorVar;

/**
 * Data specific to the thread
 */
typedef struct PcapFileThreadVars_
{
    PcapFileBehaviorVar behavior;
    bool is_directory;

    PcapFileSharedVars shared;
} PcapFileThreadVars;

static PcapFileGlobalVars pcap_g;

static TmEcode ReceivePcapFileLoop(
    ThreadVars *,
    void *,
    void *
);
static TmEcode ReceivePcapFileFileLoop(
    PcapFileThreadVars *tv,
    PcapFileFileVars *ptv
);
static TmEcode ReceivePcapFileDirectoryLoop(
    PcapFileThreadVars *tv,
    PcapFileDirectoryVars *ptv
);
static TmEcode ReceivePcapFileThreadInit(
    ThreadVars *,
    const void *,
    void **
);
static void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
static TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

static TmEcode DecodePcapFile(
    ThreadVars *,
    Packet *,
    void *,
    PacketQueue *,
    PacketQueue *
);
static TmEcode DecodePcapFileThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data);

static TmEcode InitPcapFile(PcapFileFileVars *pfv, const char *filename);
static TmEcode PcapRunStatus(PcapFileDirectoryVars *);
static void CleanupPendingFile(PendingFile *pending);
static void CleanupPcapFileDirectoryVars(
    PcapFileThreadVars *tv,
    PcapFileDirectoryVars *ptv
);
static void CleanupPcapFileFileVars(PcapFileThreadVars *tv, PcapFileFileVars *pfv);
static void CleanupPcapFileThreadVars(PcapFileThreadVars *tv);
static TmEcode PcapDirectoryFailure(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);
static TmEcode PcapDirectoryDone(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv);
static TmEcode PcapDetermineDirectoryOrFile(char *filename, DIR **directory);
static int PcapDirectoryGetModifiedTime(char const * file, struct timespec * out);
static TmEcode PcapDirectoryInsertFile(
    PcapFileDirectoryVars *pv,
    PendingFile *file_to_add,
    struct timespec *file_to_add_modified_time
);
static TmEcode PcapDirectoryPopulateBuffer(
    PcapFileDirectoryVars *ptv,
    time_t newer_than,
    time_t older_than
);
static TmEcode PcapDirectoryDispatch(
    PcapFileThreadVars *tv,
    PcapFileDirectoryVars *ptv,
    time_t *newer_than,
    time_t *older_than
);
static bool IsBefore(struct timespec *left, struct timespec *right);

/**
 * Pcap Folder Utilities
 */
TmEcode PcapRunStatus(PcapFileDirectoryVars *ptv)
{
    if(RunModeUnixSocketIsActive()) {
        if( (suricata_ctl_flags & SURICATA_STOP) ||
            UnixSocketPcapFile(TM_ECODE_OK,
                               ptv->shared->last_processed) != TM_ECODE_OK ) {
            SCReturnInt(TM_ECODE_DONE);
        }
    } else {
        if(suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_DONE);
        }
    }
    SCReturnInt(TM_ECODE_OK);
}

void CleanupPendingFile(PendingFile *pending) {
    if(pending != NULL) {
        if(pending->filename != NULL) {
            SCFree(pending->filename);
        }
        SCFree(pending);
    }
}

void CleanupPcapFileFileVars(PcapFileThreadVars *tv, PcapFileFileVars *pfv)
{
    if(pfv != NULL) {
        if (pfv->pcap_handle != NULL) {
            pcap_close(pfv->pcap_handle);
            pfv->pcap_handle = NULL;
        }
        if (pfv->filename != NULL) {
            SCFree(pfv->filename);
            pfv->filename = NULL;
        }
        pfv->shared = NULL;
        SCFree(pfv);
    }
    if (tv->is_directory == 0) {
        tv->behavior.file = NULL;
    }
}

void CleanupPcapFileDirectoryVars(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    if(ptv != NULL) {
        if (ptv->current_file != NULL) {
            CleanupPcapFileFileVars(tv, ptv->current_file);
            ptv->current_file = NULL;
        }
        if(ptv->directory != NULL) {
            closedir(ptv->directory);
            ptv->directory = NULL;
        }
        if (ptv->filename != NULL) {
            SCFree(ptv->filename);
        }
        ptv->shared = NULL;
        PendingFile *current_file = NULL;
        while (!TAILQ_EMPTY(&ptv->directory_content)) {
            current_file = TAILQ_FIRST(&ptv->directory_content);
            TAILQ_REMOVE(&ptv->directory_content, current_file, next);
            CleanupPendingFile(current_file);
        }
        SCFree(ptv);
    }
    if (tv->is_directory == 1) {
        tv->behavior.directory = NULL;
    }
}

void CleanupPcapFileThreadVars(PcapFileThreadVars *tv)
{
    if(tv != NULL) {
        if (tv->is_directory == 0) {
            if (tv->behavior.file != NULL) {
                CleanupPcapFileFileVars(tv, tv->behavior.file);
            }
            tv->behavior.file = NULL;
        } else {
            if (tv->behavior.directory != NULL) {
                CleanupPcapFileDirectoryVars(tv, tv->behavior.directory);
            }
            tv->behavior.directory = NULL;
        }
        if (tv->shared.bpf_string != NULL) {
            SCFree(tv->shared.bpf_string);
            tv->shared.bpf_string = NULL;
        }
        SCFree(tv);
    }
}

TmEcode PcapDirectoryFailure(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_FAILED;

    if(unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if(unlikely(ptv->shared == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory shared vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, ptv->shared->last_processed);
    }

    CleanupPcapFileDirectoryVars(tv, ptv);

    SCReturnInt(status);
}

TmEcode PcapDirectoryDone(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    TmEcode status = TM_ECODE_DONE;

    if(unlikely(ptv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if(unlikely(ptv->shared == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Directory shared vars was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, ptv->shared->last_processed);
    }

    CleanupPcapFileDirectoryVars(tv, ptv);

    SCReturnInt(status);
}

TmEcode PcapDetermineDirectoryOrFile(char *filename, DIR **directory)
{
    DIR *temp_dir = NULL;
    TmEcode return_code = TM_ECODE_FAILED;

    temp_dir = opendir(filename);

    if (temp_dir == NULL) //if null, our filename may just be a normal file
    {
        switch (errno)
        {
            case EACCES:
                SCLogError(SC_ERR_FOPEN, "%s: Permission denied",
                           filename);
                break;

            case EBADF:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Not a valid file descriptor opened for reading",
                           filename);
                break;

            case EMFILE:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Per process open file descriptor limit reached",
                           filename);
                break;

            case ENFILE:
                SCLogError(SC_ERR_FOPEN,
                           "%s: System wide open file descriptor limit reached",
                           filename);
                break;

            case ENOENT:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Does not exist, or name is an empty string",
                           filename);
                break;
            case ENOMEM:
                SCLogError(SC_ERR_FOPEN,
                           "%s: Insufficient memory to complete the operation",
                           filename);
                break;

            case ENOTDIR: //no error checking the directory, just is a plain file
                SCLogInfo("%s: Plain file, not a directory", filename);
                return_code = TM_ECODE_OK;
                break;

            default:
                SCLogError(SC_ERR_FOPEN, "%s: %" PRId32, filename, errno);
        }
    } else {
        //no error, filename references a directory
        *directory = temp_dir;
        return_code = TM_ECODE_OK;
    }

    return return_code;
}

int PcapDirectoryGetModifiedTime(char const * file, struct timespec * out)
{
    struct stat buf;
    int ret;

    if (file == NULL)
        return -1;

    if ((ret = stat(file, &buf)) != 0)
        return ret;

#ifdef OS_DARWIN
    *out = buf.st_mtimespec;
#else
    *out = buf.st_mtim;
#endif

    return ret;
}

bool IsBefore(struct timespec *left, struct timespec *right)
{
    return left->tv_sec < right->tv_sec ||
    (
        left->tv_sec == right->tv_sec &&
        left->tv_nsec < right->tv_nsec
    );
}

TmEcode PcapDirectoryInsertFile(
    PcapFileDirectoryVars *pv,
    PendingFile *file_to_add,
    struct timespec *file_to_add_modified_time
) {
    PendingFile *file_to_compare = NULL;
    PendingFile *next_file_to_compare = NULL;

    if(unlikely(pv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory vars passed");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if(unlikely(file_to_add == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "File passed was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if(unlikely(file_to_add->filename == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "File was passed with null filename");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogDebug("Inserting %s into directory buffer", file_to_add->filename);

    if(TAILQ_EMPTY(&pv->directory_content)) {
        TAILQ_INSERT_TAIL(&pv->directory_content, file_to_add, next);
    } else {
        file_to_compare = TAILQ_FIRST(&pv->directory_content);
        while(file_to_compare != NULL) {
            struct timespec modified_time;
            if(PcapDirectoryGetModifiedTime(file_to_compare->filename,
                                            &modified_time) == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            if(IsBefore(file_to_add_modified_time, &modified_time)) {
                TAILQ_INSERT_BEFORE(file_to_compare, file_to_add, next);
                file_to_compare = NULL;
            } else {
                next_file_to_compare = TAILQ_NEXT(file_to_compare, next);
                if (next_file_to_compare == NULL) {
                    TAILQ_INSERT_AFTER(&pv->directory_content, file_to_compare,
                                       file_to_add, next);
                }
                file_to_compare = next_file_to_compare;
            }
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode PcapDirectoryPopulateBuffer(
        PcapFileDirectoryVars *pv,
        time_t newer_than,
        time_t older_than
) {
    if(unlikely(pv == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory vars passed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    if(unlikely(pv->filename == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No directory filename was passed");
        SCReturnInt(TM_ECODE_FAILED);
    }
    struct dirent * dir = NULL;
    PendingFile *file_to_add = NULL;

    while ((dir = readdir(pv->directory)) != NULL)
    {
        if (dir->d_type != DT_REG)
        {
            continue;
        }

        char pathbuff[PATH_MAX] = {0};

        int written = 0;

        written = snprintf(pathbuff, PATH_MAX, "%s/%s", pv->filename, dir->d_name);

        if (written > 0 && written < PATH_MAX)
        {
            struct timespec temp_time;

            if (PcapDirectoryGetModifiedTime(pathbuff, &temp_time) == 0)
            {
                SCLogDebug("File %s time (%lu > %lu < %lu)", pathbuff,
                           newer_than, temp_time.tv_sec, older_than);

                // Skip files outside of our time range
                if (temp_time.tv_sec < newer_than) {
                    SCLogDebug("Skipping old file %s", pathbuff);
                    continue;
                }
                else if (temp_time.tv_sec >= older_than) {
                    SCLogDebug("Skipping new file %s", pathbuff);
                    continue;
                }
            } else {
                SCLogDebug("Unable to get modified time on %s, skipping", pathbuff);
                continue;
            }

            file_to_add = SCMalloc(sizeof(PendingFile));
            if(unlikely(file_to_add == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate pending file");

                SCReturnInt(TM_ECODE_FAILED);
            }

            file_to_add->filename = SCStrdup(pathbuff);
            if(unlikely(file_to_add->filename == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to copy filename");

                SCReturnInt(TM_ECODE_FAILED);
            }

            SCLogDebug("Found \"%s\"", file_to_add->filename);

            if(PcapDirectoryInsertFile(pv, file_to_add, &temp_time) == TM_ECODE_FAILED) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to add file");
                SCReturnInt(TM_ECODE_FAILED);
            }
        }
        else
        {
            SCLogError(SC_ERR_SPRINTF, "Could not write path");
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    SCReturnInt(TM_ECODE_OK);
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
            SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s for %s",
                       r, pcap_geterr(ptv->pcap_handle), ptv->filename);
            if (ptv->shared->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            loop_result = TM_ECODE_DONE;
        } else if (unlikely(r == 0)) {
            SCLogInfo("pcap file %s end of file reached (pcap err code %" PRId32 ")",
                      ptv->filename, r);
            tv->shared.files++;
            loop_result = TM_ECODE_DONE;
        } else if (ptv->shared->cb_result == TM_ECODE_FAILED) {
            SCLogError(SC_ERR_PCAP_DISPATCH,
                       "Pcap callback PcapFileCallbackLoop failed for %s", ptv->filename);
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
            SCLogError(SC_ERR_BPF, "bpf compilation error %s for %s",
                       pcap_geterr(pfv->pcap_handle), pfv->filename);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (pcap_setfilter(pfv->pcap_handle, &pfv->filter) < 0) {
            SCLogError(SC_ERR_BPF,"could not set bpf filter %s for %s",
                       pcap_geterr(pfv->pcap_handle), pfv->filename);
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
                    "(yet) supported in module PcapFile for %s.", pfv->datalink,
                       pfv->filename);
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
        time_t *older_than
)
{
    if(PcapDirectoryPopulateBuffer(pv, *newer_than, *older_than) == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Failed to populate directory buffer");
        SCReturnInt(TM_ECODE_FAILED);
    }

    TmEcode status = TM_ECODE_OK;

    if(TAILQ_EMPTY(&pv->directory_content)) {
        SCLogInfo("Directory %s has no files to process", pv->filename);
        *older_than = time(NULL) - pv->delay;
        rewinddir(pv->directory);
        status = TM_ECODE_OK;
    } else {
        PendingFile *current_file = NULL;

        while (status == TM_ECODE_OK && !TAILQ_EMPTY(&pv->directory_content)) {
            current_file = TAILQ_FIRST(&pv->directory_content);
            TAILQ_REMOVE(&pv->directory_content, current_file, next);

            if(unlikely(current_file == NULL)) {
                SCLogWarning(SC_ERR_PCAP_DISPATCH, "Current file was null");
            } else if(unlikely(current_file->filename == NULL)) {
                SCLogWarning(SC_ERR_PCAP_DISPATCH, "Current file filename was null");
            } else {
                SCLogDebug("Processing file %s", current_file->filename);

                PcapFileFileVars *pftv = SCMalloc(sizeof(PcapFileFileVars));
                if (unlikely(pftv == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate PcapFileFileVars");
                    SCReturnInt(TM_ECODE_FAILED);
                }
                memset(pftv, 0, sizeof(PcapFileFileVars));

                pftv->shared = pv->shared;

                if (InitPcapFile(pftv, current_file->filename) == TM_ECODE_FAILED) {
                    SCLogWarning(SC_ERR_PCAP_DISPATCH,
                                 "Failed to init pcap file %s, skipping",
                                 current_file->filename);
                    CleanupPendingFile(current_file);
                    CleanupPcapFileFileVars(tv, pftv);
                    status = TM_ECODE_OK;
                } else {

                    pv->current_file = pftv;

                    if (ReceivePcapFileFileLoop(tv, pftv) == TM_ECODE_FAILED) {
                        CleanupPendingFile(current_file);
                        CleanupPcapFileFileVars(tv, pftv);
                        SCReturnInt(TM_ECODE_FAILED);
                    }

                    CleanupPendingFile(current_file);
                    CleanupPcapFileFileVars(tv, pftv);
                    pv->current_file = NULL;

                    struct timespec temp_time;

                    if (PcapDirectoryGetModifiedTime(current_file->filename,
                                                     &temp_time) != 0) {
                        temp_time.tv_sec = *newer_than;
                    }
                    SCLogDebug("Processed file %s, processed up to %ld",
                               current_file->filename, temp_time.tv_sec);
                    pv->shared->last_processed = temp_time.tv_sec;

                    status = PcapRunStatus(pv);
                }
            }
        }

        *newer_than = *older_than;
    }
    *older_than = time(NULL) - pv->delay;

    SCReturnInt(status);
}

TmEcode ReceivePcapFileDirectoryLoop(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    SCEnter();

    time_t newer_than = 0;
    time_t older_than = INT_MAX;
    uint32_t poll_seconds = (uint32_t)localtime(&ptv->poll_interval)->tm_sec;

    if(ptv->should_loop) {
        older_than = time(NULL) - ptv->delay;
    }
    TmEcode status = TM_ECODE_OK;

    while (status == TM_ECODE_OK) {
        //loop while directory is ok
        SCLogInfo("Processing pcaps directory %s, files must be newer than %ld and older than %ld",
                  ptv->filename, newer_than, older_than);
        status = PcapDirectoryDispatch(tv, ptv, &newer_than, &older_than);
        if(ptv->should_loop && status == TM_ECODE_OK) {
            sleep(poll_seconds);
            //update our status based on suricata control flags or unix command socket
            status = PcapRunStatus(ptv);
            if(status == TM_ECODE_OK) {
                SCLogDebug("Checking if directory %s still exists", ptv->filename);
                //check directory
                if(PcapDetermineDirectoryOrFile(ptv->filename,
                                                &(ptv->directory)) == TM_ECODE_FAILED) {
                    SCLogInfo("Directory %s no longer exists, stopping",
                              ptv->filename);
                    status = TM_ECODE_DONE;
                }
            }
        } else if(status == TM_ECODE_OK) { //not looping, mark done
            SCLogDebug("Not looping, stopping directory mode");
            status = TM_ECODE_DONE;
        }
    }

    StatsSyncCountersIfSignalled(ptv->shared->tv);

    if(status == TM_ECODE_FAILED) {
        SCLogError(SC_ERR_PCAP_DISPATCH, "Directory %s run mode failed", ptv->filename);
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
        if (!RunModeUnixSocketIsActive()) {
            EngineStop();
        } else {
            status = UnixSocketPcapFile(status, ptv->shared.last_processed);
        }
        CleanupPcapFileFileVars(ptv, ptv->behavior.file);
    } else {
        SCLogInfo("Starting directory run for %s", ptv->behavior.directory->filename);
        status = ReceivePcapFileDirectoryLoop(ptv, ptv->behavior.directory);
    }

    SCLogDebug("Pcap file loop complete with status %u", status);

    if(RunModeUnixSocketIsActive()) {
        SCReturnInt(TM_ECODE_DONE);
    } else {
        EngineStop();
        SCReturnInt(TM_ECODE_OK);
    }
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
    if(PcapDetermineDirectoryOrFile((char *)initdata, &directory) == TM_ECODE_FAILED) {
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
            SCLogWarning(SC_ERR_PCAP_DISPATCH,
                         "Failed to init pcap file %s, skipping", (char *)initdata);
            CleanupPcapFileFileVars(ptv, pv);
            SCReturnInt(init_file_return);
        }
    } else {
        SCLogInfo("Argument %s was a directory", (char *)initdata);
        PcapFileDirectoryVars *pv = SCMalloc(sizeof(PcapFileDirectoryVars));
        if (unlikely(pv == NULL))
            SCReturnInt(TM_ECODE_FAILED);
        memset(pv, 0, sizeof(PcapFileDirectoryVars));

        int should_loop = 0;
        pv->should_loop = false;
        if (ConfGetBool("pcap-file.continuous", &should_loop) == 1) {
            pv->should_loop = should_loop == 1;
        }

        pv->delay = 30;
        intmax_t delay = 0;
        if (ConfGetInt("pcap-file.delay", &delay) == 1) {
            if (delay > 0 && delay < UINT_MAX) {
                pv->delay = (time_t)delay;
                SCLogDebug("delay %lu", pv->delay);
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "delay out of range");
            }
        }

        pv->poll_interval = 5;
        intmax_t poll_interval = 0;
        if (ConfGetInt("pcap-file.poll-interval", &poll_interval) == 1) {
            if (poll_interval > 0 && poll_interval < UINT_MAX) {
                pv->poll_interval = (time_t)poll_interval;
                SCLogDebug("poll-interval %lu", pv->delay);
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
        TAILQ_INIT(&pv->directory_content);

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
    CleanupPcapFileThreadVars(ptv);
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
            SCLogError(
                SC_ERR_UNIMPLEMENTED,
                "datalink type %" PRId32 " not (yet) supported in module PcapFile.",
                p->datalink
            );
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
