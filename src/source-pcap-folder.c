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

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "source-pcap-folder.h"
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

#ifdef __SC_CUDA_SUPPORT__

#include "util-cuda.h"
#include "util-cuda-buffer.h"
#include "util-mpm-ac.h"
#include "util-cuda-handlers.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-cuda-vars.h"

#endif /* __SC_CUDA_SUPPORT__ */

#include <dirent.h> // dirent
#include <limits.h> // PATH_MAX
#include <sys/types.h>  // stat
#include <sys/stat.h>   // stat
#include <unistd.h>     // stat

#ifdef __linux__
#  include <linux/version.h>
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21)
#    define PCAP_FOLDER_ENABLE_MONITOR
#    include <sys/inotify.h> // inotify
#  endif
#endif
#include "util-buffer.h"

extern int max_pending_packets;

typedef struct PcapFolderGlobalVars_ {
    pcap_t *pcap_handle;
    int (*Decoder)(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
    int datalink;
    struct bpf_program filter;
    uint64_t cnt; /** packet counter */
    ChecksumValidationMode conf_checksum_mode;
    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, invalid_checksums);

    char * dirpath;

} PcapFolderGlobalVars;

typedef struct PcapFolderThreadVars_
{
    uint32_t tenant_id;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;

    ThreadVars *tv;
    TmSlot *slot;

    /** callback result -- set if one of the thread module failed. */
    int cb_result;

    uint8_t done;
    uint32_t errs;
} PcapFolderThreadVars;

static PcapFolderGlobalVars pcap_g;

TmEcode ReceivePcapFolderLoop(ThreadVars *, void *, void *);

TmEcode ReceivePcapFolderThreadInit(ThreadVars *, void *, void **);
void ReceivePcapFolderThreadExitStats(ThreadVars *, void *);
TmEcode ReceivePcapFolderThreadDeinit(ThreadVars *, void *);

TmEcode DecodePcapFolder(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DecodePcapFolderThreadInit(ThreadVars *, void *, void **);
TmEcode DecodePcapFolderThreadDeinit(ThreadVars *tv, void *data);

void TmModuleReceivePcapFolderRegister (void)
{
    tmm_modules[TMM_RECEIVEPCAPFOLDER].name = "ReceivePcapFolder";
    tmm_modules[TMM_RECEIVEPCAPFOLDER].ThreadInit = ReceivePcapFolderThreadInit;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].Func = NULL;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].PktAcqLoop = ReceivePcapFolderLoop;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].ThreadExitPrintStats = ReceivePcapFolderThreadExitStats;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].ThreadDeinit = ReceivePcapFolderThreadDeinit;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].RegisterTests = NULL;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].cap_flags = 0;
    tmm_modules[TMM_RECEIVEPCAPFOLDER].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodePcapFolderRegister (void)
{
    tmm_modules[TMM_DECODEPCAPFOLDER].name = "DecodePcapFolder";
    tmm_modules[TMM_DECODEPCAPFOLDER].ThreadInit = DecodePcapFolderThreadInit;
    tmm_modules[TMM_DECODEPCAPFOLDER].Func = DecodePcapFolder;
    tmm_modules[TMM_DECODEPCAPFOLDER].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODEPCAPFOLDER].ThreadDeinit = DecodePcapFolderThreadDeinit;
    tmm_modules[TMM_DECODEPCAPFOLDER].RegisterTests = NULL;
    tmm_modules[TMM_DECODEPCAPFOLDER].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAPFOLDER].flags = TM_FLAG_DECODE_TM;
}

void PcapFolderGlobalInit()
{
    memset(&pcap_g, 0x00, sizeof(pcap_g));
    SC_ATOMIC_INIT(pcap_g.invalid_checksums);
}

void PcapFolderCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();

    PcapFolderThreadVars *ptv = (PcapFolderThreadVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }
    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFOLDER);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = h->ts.tv_sec;
    p->ts.tv_usec = h->ts.tv_usec;
    SCLogDebug("p->ts.tv_sec %"PRIuMAX"", (uintmax_t)p->ts.tv_sec);
    p->datalink = pcap_g.datalink;
    p->pcap_cnt = ++pcap_g.cnt;

    p->pcap_v.tenant_id = ptv->tenant_id;
    ptv->pkts++;
    ptv->bytes += h->caplen;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->tv, p);
        PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFOLDER);
        SCReturn;
    }

    /* We only check for checksum disable */
    if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->pkts, p->pcap_cnt,
                                  SC_ATOMIC_GET(pcap_g.invalid_checksums))) {
            pcap_g.checksum_mode = CHECKSUM_VALIDATION_DISABLE;
            p->flags |= PKT_IGNORE_CHECKSUM;
        }
    }

    PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFOLDER);

    if (TmThreadsSlotProcessPkt(ptv->tv, ptv->slot, p) != TM_ECODE_OK) {
        pcap_breakloop(pcap_g.pcap_handle);
        ptv->cb_result = TM_ECODE_FAILED;
    }

    SCReturn;
}

int PcapFolderGetModifiedTime(char const * file, time_t * out)
{
    struct stat buf;
    int ret;

    if (file == NULL)
        return -1;

    SCLogInfo("PcapFolderGetModifiedTime \"%s\"", file);

    if ((ret = stat(file, &buf)) != 0)
        return ret;

    *out = buf.st_mtime;

    return ret;
}

int PcapFolderSortByStatTime(const void * vleft, const void * vright)
{
    if (vleft == vright)
        return 0;

    time_t leftTime = 0, rightTime = 0;

    int leftRet, rightRet;

    leftRet = PcapFolderGetModifiedTime(*(const char **)vleft, &leftTime);
    rightRet = PcapFolderGetModifiedTime(*(const char **)vright, &rightTime);

    if (leftRet == 0 && rightRet == 0)
    {
        return (leftTime == rightTime) ? 0 : ((leftTime < rightTime) ? -1 : 1);
    }
    else
    {
        return (leftRet == rightRet) ? 0 : ((leftRet < rightRet) ? -1 : 1);
    }
}

void PcapFolderFreeMemBuffer(MemBuffer * buffer)
{
    if (buffer == NULL)
        return;
    
    size_t offset = 0;

    while (offset < MEMBUFFER_OFFSET(buffer))
    {
        SCFree(*((char**)(MEMBUFFER_BUFFER(buffer) + offset)));
        offset += sizeof(char*);
    }
    MemBufferFree(buffer);
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode ReceivePcapFolderLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    int packet_q_len = 64;
    PcapFolderThreadVars *ptv = (PcapFolderThreadVars *)data;
    int r;
    TmSlot *s = (TmSlot *)slot;

    ptv->slot = s->slot_next;
    ptv->cb_result = TM_ECODE_OK;

    time_t newerThan = 0;

    while (1) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        time_t const fileDelay = 30;
        time_t olderThan = time(NULL);
        olderThan -= fileDelay;
        time_t firstNewFileTime = 0;
        time_t lastProcessed = 0;

        DIR * directory = NULL;

        directory = opendir(pcap_g.dirpath);
        if (directory == NULL)
        {
            switch (errno)
            {
                case EACCES:
                SCLogError(SC_ERR_FOPEN, "Permission denied\n");
                break;

                case EBADF:
                SCLogError(SC_ERR_FOPEN, "Not a valid file descriptor opened for reading\n");
                break;

                case EMFILE:
                SCLogError(SC_ERR_FOPEN, "The per-process limit on the number of open file descriptors has been reached\n");
                break;

                case ENFILE:
                SCLogError(SC_ERR_FOPEN, "The system-wide limit on the number of open file descriptors has been reached\n");
                break;

                case ENOENT:
                SCLogError(SC_ERR_FOPEN, "Directory does not exist, or name is an empty string\n");
                break;
                case ENOMEM:
                SCLogError(SC_ERR_FOPEN, "Insufficient memory to complete the operation\n");
                break;

                case ENOTDIR:
                SCLogError(SC_ERR_FOPEN, "Not a directory\n");
                break;

                default:
                SCLogError(SC_ERR_FOPEN, "%" PRId32 "\n", errno);
            }

            SCFree(pcap_g.dirpath);
            if (ptv->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            if (!RunModeUnixSocketIsActive()) {
                EngineStop();
            } else {
                UnixSocketPcapFolder(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        }

        struct dirent * dir = NULL;

        MemBuffer * directory_content = NULL;

        while ((dir = readdir(directory)) != NULL)
        {
            if (dir->d_type != DT_REG)
            {
                continue;
            }

            char pathbuff[PATH_MAX] = {0};

            int written;
            written = snprintf(pathbuff, PATH_MAX, "%s/%s", pcap_g.dirpath, dir->d_name);

            if (written > 0 && written < PATH_MAX)
            {
                time_t tempTime = 0;
                
                if (PcapFolderGetModifiedTime(pathbuff, &tempTime) == 0)
                {
                    SCLogInfo("Folder %s time (%lu > %lu < %lu)", pathbuff, newerThan, tempTime, olderThan);

                    // Skip files outside of our time range
                    if (tempTime < newerThan)
                    {
                        SCLogInfo("Skipping old file %s", pathbuff);
                        continue;
                    }
                    else if (tempTime > olderThan)
                    {
                        SCLogInfo("Skipping new file %s", pathbuff);
                        if (tempTime < firstNewFileTime || firstNewFileTime == 0)
                        {
                            firstNewFileTime = tempTime;
                        }
                        continue;
                    }

                    if (lastProcessed < tempTime)
                    {
                        lastProcessed = tempTime;
                    }                    
                }

                if (directory_content == NULL)
                {
                    directory_content = MemBufferCreateNew(sizeof(char*) * 32);
                    if (!directory_content)
                    {
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        
                        SCLogError(SC_ERR_FOPEN, "Failed to create buffer\n");
                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        if (!RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    }
                }
                else if (MEMBUFFER_SIZE(directory_content) - MEMBUFFER_OFFSET(directory_content) < sizeof(char*))
                {
                    // Double size
                    if (!MemBufferExpand(&directory_content, MEMBUFFER_SIZE(directory_content)))
                    {   
                        PcapFolderFreeMemBuffer(directory_content);
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        
                        SCLogError(SC_ERR_FOPEN, "Failed to expand buffer\n");
                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        if (!RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    }
                }

                char * mem = SCMalloc(written + 1);
                if (!mem)
                {
                    PcapFolderFreeMemBuffer(directory_content);
                    closedir(directory);
                    SCFree(pcap_g.dirpath);
                    
                    SCLogError(SC_ERR_FOPEN, "Failed to create file name buffer\n");
                    if (ptv->cb_result == TM_ECODE_FAILED) {
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                    if (!RunModeUnixSocketIsActive()) {
                        EngineStop();
                    } else {
                        UnixSocketPcapFolder(TM_ECODE_DONE);
                        SCReturnInt(TM_ECODE_DONE);
                    }
                }
                memcpy(mem, pathbuff, written + 1);

                SCLogInfo("Found \"%s\" %i", mem, written + 1);

                *((char**)(MEMBUFFER_BUFFER(directory_content) + MEMBUFFER_OFFSET(directory_content))) = mem;
                
                MEMBUFFER_OFFSET(directory_content) += sizeof(char *);
            }
            else 
            {
                PcapFolderFreeMemBuffer(directory_content);
                closedir(directory);
                SCFree(pcap_g.dirpath);
                
                SCLogError(SC_ERR_FOPEN, "Failed to snprintf");
                if (ptv->cb_result == TM_ECODE_FAILED) {
                    SCReturnInt(TM_ECODE_FAILED);
                }
                if (!RunModeUnixSocketIsActive()) {
                    EngineStop();
                } else {
                    UnixSocketPcapFolder(TM_ECODE_DONE);
                    SCReturnInt(TM_ECODE_DONE);
                }
            }
        }

        if (directory_content != NULL)
        {
            // Sort buffer
            qsort(MEMBUFFER_BUFFER(directory_content), MEMBUFFER_OFFSET(directory_content) / sizeof(char*), sizeof(char*), &PcapFolderSortByStatTime);

            size_t offset = 0;

            while (offset < MEMBUFFER_OFFSET(directory_content))
            {
                char * pathbuff = (*((char**)(MEMBUFFER_BUFFER(directory_content) + offset)));
                offset += sizeof(char*);

                SCLogInfo("opening \"%s\"", pathbuff);

                char errbuf[PCAP_ERRBUF_SIZE] = {0};
                pcap_g.pcap_handle = pcap_open_offline(pathbuff, errbuf);
                if (pcap_g.pcap_handle == NULL) 
                {
                    
                    PcapFolderFreeMemBuffer(directory_content);
                    closedir(directory);
                    SCFree(pcap_g.dirpath);
                    
                    SCLogError(SC_ERR_FOPEN, "%s\n", errbuf);
                    if (ptv->cb_result == TM_ECODE_FAILED) {
                        SCReturnInt(TM_ECODE_FAILED);
                    }
                    if (!RunModeUnixSocketIsActive()) {
                        EngineStop();
                    } else {
                        UnixSocketPcapFolder(TM_ECODE_DONE);
                        SCReturnInt(TM_ECODE_DONE);
                    }
                }

                char *tmpbpfstring = NULL;

                if (ConfGet("bpf-filter", &tmpbpfstring) != 1) {
                    SCLogDebug("could not get bpf or none specified");
                } else {
                    SCLogInfo("using bpf-filter \"%s\"", tmpbpfstring);

                    if (pcap_compile(pcap_g.pcap_handle, &pcap_g.filter, tmpbpfstring, 1, 0) < 0) {
                        SCLogError(SC_ERR_BPF,"bpf compilation error %s",
                                pcap_geterr(pcap_g.pcap_handle));

                        PcapFolderFreeMemBuffer(directory_content);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        
                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        if (!RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    }

                    if (pcap_setfilter(pcap_g.pcap_handle, &pcap_g.filter) < 0) {
                        SCLogError(SC_ERR_BPF,"could not set bpf filter %s", pcap_geterr(pcap_g.pcap_handle));

                        PcapFolderFreeMemBuffer(directory_content);
                        pcap_freecode(&pcap_g.filter);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        closedir(directory);
                        SCFree(pcap_g.dirpath);

                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        if (!RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    }

                    pcap_freecode(&pcap_g.filter);
                }

                pcap_g.datalink = pcap_datalink(pcap_g.pcap_handle);
                SCLogDebug("datalink %" PRId32 "", pcap_g.datalink);

                switch (pcap_g.datalink) {
                    case LINKTYPE_LINUX_SLL:
                        pcap_g.Decoder = DecodeSll;
                        break;
                    case LINKTYPE_ETHERNET:
                        pcap_g.Decoder = DecodeEthernet;
                        break;
                    case LINKTYPE_PPP:
                        pcap_g.Decoder = DecodePPP;
                        break;
                    case LINKTYPE_RAW:
                        pcap_g.Decoder = DecodeRaw;
                        break;
                    case LINKTYPE_NULL:
                        pcap_g.Decoder = DecodeNull;
                        break;

                    default:
                        SCLogError(SC_ERR_UNIMPLEMENTED, "datalink type %" PRId32 " not "
                                "(yet) supported in module PcapFolder.\n", pcap_g.datalink);

                        PcapFolderFreeMemBuffer(directory_content);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        
                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        if (!RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                }

                while (1)
                {
                    /* Right now we just support reading packets one at a time. */
                    r = pcap_dispatch(pcap_g.pcap_handle, packet_q_len,
                                    (pcap_handler)PcapFolderCallbackLoop, (u_char *)ptv);
                    if (unlikely(r == -1)) {
                        SCLogError(SC_ERR_PCAP_DISPATCH, "error code %" PRId32 " %s",
                                r, pcap_geterr(pcap_g.pcap_handle));
                        if (ptv->cb_result == TM_ECODE_FAILED) {
                            SCReturnInt(TM_ECODE_FAILED);
                        }
                        PcapFolderFreeMemBuffer(directory_content);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        if (! RunModeUnixSocketIsActive()) {
                            EngineStop();
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    } else if (unlikely(r == 0)) {
                        SCLogInfo("pcap file end of file reached (pcap err code %" PRId32 ")", r);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        break;
                    } else if (ptv->cb_result == TM_ECODE_FAILED) {
                        SCLogError(SC_ERR_PCAP_DISPATCH, "Pcap callback PcapFolderCallbackLoop failed");
                        PcapFolderFreeMemBuffer(directory_content);
                        pcap_close(pcap_g.pcap_handle);
                        pcap_g.pcap_handle = NULL;
                        closedir(directory);
                        SCFree(pcap_g.dirpath);
                        if (! RunModeUnixSocketIsActive()) {
                            SCReturnInt(TM_ECODE_FAILED);
                        } else {
                            UnixSocketPcapFolder(TM_ECODE_DONE);
                            SCReturnInt(TM_ECODE_DONE);
                        }
                    }
                }
            }

            PcapFolderFreeMemBuffer(directory_content);
        }
        closedir(directory);

        UnixSocketPcapFolderSetLastProcessed(lastProcessed);

#ifdef PCAP_FOLDER_ENABLE_MONITOR
        int shutdown = 0;
        
        int inotify_fd = inotify_init1(IN_NONBLOCK);
        if (inotify_fd == -1)
        {
            SCFree(pcap_g.dirpath);

            SCLogError(SC_ERR_PCAP_DISPATCH, "Failed to initialize directory watch");
            if (!RunModeUnixSocketIsActive()) 
            {
                EngineStop();
            } else {
                UnixSocketPcapFolder(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        }

        int watch_fd = inotify_add_watch(inotify_fd, pcap_g.dirpath, IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVE_SELF | IN_DELETE_SELF);

        if (watch_fd == -1)
        {
            close(inotify_fd);
            SCFree(pcap_g.dirpath);
            SCLogError(SC_ERR_PCAP_DISPATCH, "Failed to add directory watch");
            if (!RunModeUnixSocketIsActive()) 
            {
                EngineStop();
            } else {
                UnixSocketPcapFolder(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        }

       
        char data[sizeof(struct inotify_event) + NAME_MAX + 1];

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(inotify_fd, &fds);

        int res;
        int totalWaitTime;

        if (firstNewFileTime != 0)
        {
            totalWaitTime = (fileDelay - (time(NULL) - firstNewFileTime)) + 1;
            SCLogInfo("Waiting %u seconds for pending file", totalWaitTime);
        }
        else 
        {
            totalWaitTime = 0;
#endif // PCAP_FOLDER_ENABLE_MONITOR
            UnixSocketPcapFolder(TM_ECODE_DONE);
            SCLogInfo("Waiting for new file event");
#ifdef PCAP_FOLDER_ENABLE_MONITOR
        }

        int waitedTime = 0;
        
        do
        {
            // Some implementations change these values so needs to be set every loop iteration
            struct timeval sleep_time;
            sleep_time.tv_sec = 5;
            sleep_time.tv_usec = 0;

            res = select(FD_SETSIZE, &fds, NULL, NULL, &sleep_time);

            // Every 5 seconds check if the engine shut down and break early if it did
            if (suricata_ctl_flags & SURICATA_STOP) {
                shutdown = 1;
                break;
            }

            waitedTime += 5;
        }
        // if result = 0 (timeout)
        // and ((totalWaitTime is infinite) or (waitedTime is less than totalWaitTime)
        while (res == 0 && ((totalWaitTime == 0) || (waitedTime < totalWaitTime)));

        if (totalWaitTime == 0)
        {
#else //PCAP_FOLDER_ENABLE_MONITOR
            sleep(5);
#endif 
            UnixSocketPcapFolder(TM_ECODE_OK);
#ifdef PCAP_FOLDER_ENABLE_MONITOR
        }

        if (res > 0)
        {
            res = read(inotify_fd, &data, sizeof(data));

            if (res > 0)
            {
                SCLogInfo("Event");
                struct inotify_event * event = (struct inotify_event *)data;
                
                if ((event->mask & (IN_DELETE_SELF | IN_MOVE_SELF)) != 0)
                { 
                    shutdown = 1;
                }
            }
        }

        SCLogInfo("Resetting");

        if (inotify_rm_watch(inotify_fd, watch_fd) != 0)
        {
            close(inotify_fd);
            SCFree(pcap_g.dirpath);
            SCLogError(SC_ERR_PCAP_DISPATCH, "Failed to remove directory watch");
            if (!RunModeUnixSocketIsActive()) 
            {
                EngineStop();
            } else {
                UnixSocketPcapFolder(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_DONE);
            }
        }

        close(inotify_fd);

        if (shutdown != 0)
        {
            SCLogInfo("Shutdown");
            SCFree(pcap_g.dirpath);

            if (! RunModeUnixSocketIsActive()) 
            {
                EngineStop();
            } else {
                UnixSocketPcapFolder(TM_ECODE_DONE);
                SCReturnInt(TM_ECODE_OK);
            }
        }

        // Update window
        newerThan = olderThan;
#endif // PCAP_FOLDER_ENABLE_MONITOR
        StatsSyncCountersIfSignalled(tv);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode ReceivePcapFolderThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCEnter();

    char *tmpstring = NULL;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("reading pcap folder %s", (char *)initdata);

    PcapFolderThreadVars *ptv = SCMalloc(sizeof(PcapFolderThreadVars));
    if (unlikely(ptv == NULL))
        SCReturnInt(TM_ECODE_FAILED);
    memset(ptv, 0, sizeof(PcapFolderThreadVars));

    intmax_t tenant = 0;
    if (ConfGetInt("pcap-folder.tenant-id", &tenant) == 1) {
        if (tenant > 0 && tenant < UINT_MAX) {
            ptv->tenant_id = (uint32_t)tenant;
            SCLogInfo("tenant %u", ptv->tenant_id);
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "tenant out of range");
        }
    }

    size_t len = strlen((char*)initdata);

    pcap_g.dirpath = SCMalloc(len + 1);
    memcpy(pcap_g.dirpath, initdata, len);
    pcap_g.dirpath[len] = 0;

    if (ConfGet("pcap-folder.checksum-checks", &tmpstring) != 1) {
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

    ptv->tv = tv;
    *data = (void *)ptv;

    SCReturnInt(TM_ECODE_OK);
}

void ReceivePcapFolderThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFolderThreadVars *ptv = (PcapFolderThreadVars *)data;

    if (pcap_g.conf_checksum_mode == CHECKSUM_VALIDATION_AUTO &&
            pcap_g.cnt < CHECKSUM_SAMPLE_COUNT &&
            SC_ATOMIC_GET(pcap_g.invalid_checksums)) {
        uint64_t chrate = pcap_g.cnt / SC_ATOMIC_GET(pcap_g.invalid_checksums);
        if (chrate < CHECKSUM_INVALID_RATIO)
            SCLogWarning(SC_ERR_INVALID_CHECKSUM,
                         "1/%" PRIu64 "th of packets have an invalid checksum,"
                         " consider setting pcap-folder.checksum-checks variable to no"
                         " or use '-k none' option on command line.",
                         chrate);
        else
            SCLogInfo("1/%" PRIu64 "th of packets have an invalid checksum",
                      chrate);
    }
    SCLogNotice("Pcap-folder module read %" PRIu32 " packets, %" PRIu64 " bytes", ptv->pkts, ptv->bytes);
    return;
}

TmEcode ReceivePcapFolderThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    PcapFolderThreadVars *ptv = (PcapFolderThreadVars *)data;
    if (ptv) {
        SCFree(ptv);
    }
    SCReturnInt(TM_ECODE_OK);
}

static double prev_signaled_ts = 0;

TmEcode DecodePcapFolder(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
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

    /* call the decoder */
    pcap_g.Decoder(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);

#ifdef DEBUG
    BUG_ON(p->pkt_src != PKT_SRC_WIRE && p->pkt_src != PKT_SRC_FFR);
#endif

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DecodePcapFolderThreadInit(ThreadVars *tv, void *initdata, void **data)
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

TmEcode DecodePcapFolderThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

void PcapFolderIncreaseInvalidChecksum()
{
    (void) SC_ATOMIC_ADD(pcap_g.invalid_checksums, 1);
}

/* eof */

