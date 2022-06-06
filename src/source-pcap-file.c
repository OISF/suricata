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
#include "source-pcap-file.h"
#include "source-pcap-file-helper.h"
#include "source-pcap-file-directory-helper.h"
#include "flow-manager.h"
#include "util-checksum.h"

extern int max_pending_packets;
PcapFileGlobalVars pcap_g;

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

static TmEcode ReceivePcapFileLoop(ThreadVars *, void *, void *);
static TmEcode ReceivePcapFileThreadInit(ThreadVars *, const void *, void **);
static void ReceivePcapFileThreadExitStats(ThreadVars *, void *);
static TmEcode ReceivePcapFileThreadDeinit(ThreadVars *, void *);

static TmEcode DecodePcapFile(ThreadVars *, Packet *, void *);
static TmEcode DecodePcapFileThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodePcapFileThreadDeinit(ThreadVars *tv, void *data);

static void CleanupPcapDirectoryFromThreadVars(PcapFileThreadVars *tv,
                                               PcapFileDirectoryVars *ptv);
static void CleanupPcapFileFromThreadVars(PcapFileThreadVars *tv, PcapFileFileVars *pfv);
static void CleanupPcapFileThreadVars(PcapFileThreadVars *tv);
static TmEcode PcapFileExit(TmEcode status, struct timespec *last_processed);

void CleanupPcapFileFromThreadVars(PcapFileThreadVars *tv, PcapFileFileVars *pfv)
{
    CleanupPcapFileFileVars(pfv);
    if (tv->is_directory == 0) {
        tv->behavior.file = NULL;
    }
}

void CleanupPcapDirectoryFromThreadVars(PcapFileThreadVars *tv, PcapFileDirectoryVars *ptv)
{
    CleanupPcapFileDirectoryVars(ptv);
    if (tv->is_directory == 1) {
        tv->behavior.directory = NULL;
    }
}

void CleanupPcapFileThreadVars(PcapFileThreadVars *tv)
{
    if(tv != NULL) {
        if (tv->is_directory == 0) {
            if (tv->behavior.file != NULL) {
                CleanupPcapFileFromThreadVars(tv, tv->behavior.file);
            }
            tv->behavior.file = NULL;
        } else {
            if (tv->behavior.directory != NULL) {
                CleanupPcapDirectoryFromThreadVars(tv, tv->behavior.directory);
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
    tmm_modules[TMM_DECODEPCAPFILE].cap_flags = 0;
    tmm_modules[TMM_DECODEPCAPFILE].flags = TM_FLAG_DECODE_TM;
}

void PcapFileGlobalInit()
{
    memset(&pcap_g, 0x00, sizeof(pcap_g));
    SC_ATOMIC_INIT(pcap_g.invalid_checksums);
}

TmEcode PcapFileExit(TmEcode status, struct timespec *last_processed)
{
    if(RunModeUnixSocketIsActive()) {
        status = UnixSocketPcapFile(status, last_processed);
        SCReturnInt(status);
    } else {
        EngineStop();
        SCReturnInt(status);
    }
}

TmEcode ReceivePcapFileLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();

    if(unlikely(data == NULL)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "pcap file reader thread failed to initialize");

        PcapFileExit(TM_ECODE_FAILED, NULL);

        SCReturnInt(TM_ECODE_DONE);
    }

    TmEcode status = TM_ECODE_OK;
    PcapFileThreadVars *ptv = (PcapFileThreadVars *) data;
    TmSlot *s = (TmSlot *)slot;

    ptv->shared.slot = s->slot_next;
    ptv->shared.cb_result = TM_ECODE_OK;

    // Indicate that the thread is actually running its application level code (i.e., it can poll
    // packets)
    TmThreadsSetFlag(tv, THV_RUNNING);

    if(ptv->is_directory == 0) {
        SCLogInfo("Starting file run for %s", ptv->behavior.file->filename);
        status = PcapFileDispatch(ptv->behavior.file);
        CleanupPcapFileFromThreadVars(ptv, ptv->behavior.file);
    } else {
        SCLogInfo("Starting directory run for %s", ptv->behavior.directory->filename);
        PcapDirectoryDispatch(ptv->behavior.directory);
        CleanupPcapDirectoryFromThreadVars(ptv, ptv->behavior.directory);
    }

    SCLogDebug("Pcap file loop complete with status %u", status);

    status = PcapFileExit(status, &ptv->shared.last_processed);
    SCReturnInt(status);
}

TmEcode ReceivePcapFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    TmEcode status = TM_ECODE_OK;
    const char *tmpstring = NULL;
    const char *tmp_bpf_string = NULL;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "error: initdata == NULL");

        SCReturnInt(TM_ECODE_OK);
    }

    PcapFileThreadVars *ptv = SCMalloc(sizeof(PcapFileThreadVars));
    if (unlikely(ptv == NULL)) {
        SCReturnInt(TM_ECODE_OK);
    }
    memset(ptv, 0, sizeof(PcapFileThreadVars));
    memset(&ptv->shared.last_processed, 0, sizeof(struct timespec));

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

            CleanupPcapFileThreadVars(ptv);

            SCReturnInt(TM_ECODE_OK);
        }
    }

    int should_delete = 0;
    ptv->shared.should_delete = false;
    if (ConfGetBool("pcap-file.delete-when-done", &should_delete) == 1) {
        ptv->shared.should_delete = should_delete == 1;
    }

    DIR *directory = NULL;
    SCLogDebug("checking file or directory %s", (char*)initdata);
    if(PcapDetermineDirectoryOrFile((char *)initdata, &directory) == TM_ECODE_FAILED) {
        CleanupPcapFileThreadVars(ptv);
        SCReturnInt(TM_ECODE_OK);
    }

    if(directory == NULL) {
        SCLogDebug("argument %s was a file", (char *)initdata);
        PcapFileFileVars *pv = SCMalloc(sizeof(PcapFileFileVars));
        if (unlikely(pv == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate file vars");
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_OK);
        }
        memset(pv, 0, sizeof(PcapFileFileVars));

        pv->filename = SCStrdup((char *)initdata);
        if (unlikely(pv->filename == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate filename");
            CleanupPcapFileFileVars(pv);
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_OK);
        }

        pv->shared = &ptv->shared;
        status = InitPcapFile(pv);
        if(status == TM_ECODE_OK) {
            ptv->is_directory = 0;
            ptv->behavior.file = pv;
        } else {
            SCLogWarning(SC_ERR_PCAP_DISPATCH,
                         "Failed to init pcap file %s, skipping", pv->filename);
            CleanupPcapFileFileVars(pv);
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_OK);
        }
    } else {
        SCLogInfo("Argument %s was a directory", (char *)initdata);
        PcapFileDirectoryVars *pv = SCMalloc(sizeof(PcapFileDirectoryVars));
        if (unlikely(pv == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate directory vars");
            closedir(directory);
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_OK);
        }
        memset(pv, 0, sizeof(PcapFileDirectoryVars));

        pv->filename = SCStrdup((char*)initdata);
        if (unlikely(pv->filename == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate filename");
            CleanupPcapFileDirectoryVars(pv);
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_OK);
        }
        pv->cur_dir_depth = 0;

        int should_recurse;
        pv->should_recurse = false;
        if (ConfGetBool("pcap-file.recursive", &should_recurse) == 1) {
            pv->should_recurse = (should_recurse == 1);
        }

        int should_loop = 0;
        pv->should_loop = false;
        if (ConfGetBool("pcap-file.continuous", &should_loop) == 1) {
            pv->should_loop = (should_loop == 1);
        }

        if (pv->should_recurse == true && pv->should_loop == true) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Error, --pcap-file-continuous and --pcap-file-recursive "
                                                "cannot be used together.");
            CleanupPcapFileDirectoryVars(pv);
            CleanupPcapFileThreadVars(ptv);
            SCReturnInt(TM_ECODE_FAILED);
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
    if(data != NULL) {
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
}

TmEcode ReceivePcapFileThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    if(data != NULL) {
        PcapFileThreadVars *ptv = (PcapFileThreadVars *) data;
        CleanupPcapFileThreadVars(ptv);
    }
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodePcapFile(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    /* update counters */
    DecodeUpdatePacketCounters(tv, dtv, p);

    DecoderFunc decoder;
    if(ValidateLinkType(p->datalink, &decoder) == TM_ECODE_OK) {

        /* call the decoder */
        decoder(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

#ifdef DEBUG
        BUG_ON(p->pkt_src != PKT_SRC_WIRE && p->pkt_src != PKT_SRC_FFR);
#endif

        PacketDecodeFinalize(tv, dtv, p);

        SCReturnInt(TM_ECODE_OK);
    } else {
        SCReturnInt(TM_ECODE_FAILED);
    }
}

TmEcode DecodePcapFileThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);

    if (dtv == NULL)
        SCReturnInt(TM_ECODE_FAILED);

    DecodeRegisterPerfCounters(dtv, tv);

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
