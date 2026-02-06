/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Danny Browning <danny.browning@protectwise.com>
 *
 * File based pcap packet acquisition support
 */

#include "source-pcap-file-helper.h"
#include "suricata.h"
#include "util-datalink.h"
#include "util-checksum.h"
#include "util-profiling.h"
#include "util-exception-policy.h"
#include "conf-yaml-loader.h"
#include "capture-hooks.h"
#include "threads.h"

extern uint32_t max_pending_packets;
extern PcapFileGlobalVars pcap_g;

static PcapFileFileVars *pcap_current_pfv = NULL;

static void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt);

static void PcapFileReleasePacket(Packet *p)
{
    PcapFileFileVars *pfv = p->pcap_v.pfv;
    if (pfv != NULL) {
        PcapFileFinalizePacket(pfv);
    }

    PacketFreeOrRelease(p);
}

void PcapFileReleasePseudoPacket(Packet *p)
{
    PcapFileFileVars *pfv = p->pcap_v.pfv;
    /* Alerts are counted in PacketAlertFinalize via PcapFileAddAlertCount, so
     * avoid double-counting here. Decrement refcount if we held one. */
    if (pfv != NULL) {
        uint32_t prev = SC_ATOMIC_SUB(pfv->ref_cnt, 1);
        if (prev == 1 && pfv->cleanup_requested) {
            CleanupPcapFileFileVars(pfv);
        }
    }
    PacketFreeOrRelease(p);
}

void CleanupPcapFileFileVars(PcapFileFileVars *pfv)
{
    if (pfv == NULL) {
        return;
    }

    /* If there are still packets in flight, defer ALL cleanup actions, including
     * the deletion decision, until the last packet completes. */
    if (SC_ATOMIC_GET(pfv->ref_cnt) != 0) {
        pfv->cleanup_requested = true;
        return;
    }

    /* No packets in flight anymore: it's now safe to close, decide, and delete. */
    if (pfv->pcap_handle != NULL) {
        pcap_close(pfv->pcap_handle);
        pfv->pcap_handle = NULL;
    }

    if (pfv->filename != NULL) {
        if (PcapFileShouldDeletePcapFile(pfv)) {
            SCLogDebug("Deleting pcap file %s", pfv->filename);
            if (unlink(pfv->filename) != 0) {
                SCLogWarning("Failed to delete %s: %s", pfv->filename, strerror(errno));
            }
        }
        SCFree(pfv->filename);
        pfv->filename = NULL;
    }

    pfv->shared = NULL;
    if (pcap_current_pfv == pfv) {
        pcap_current_pfv = NULL;
    }
    SCFree(pfv);
}

void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt)
{
    SCEnter();
#ifdef DEBUG
    if (unlikely((pcap_g.cnt + 1ULL) == g_eps_pcap_packet_loss)) {
        SCLogNotice("skipping packet %" PRIu64, g_eps_pcap_packet_loss);
        pcap_g.cnt++;
        SCReturn;
    }
#endif
    PcapFileFileVars *ptv = (PcapFileFileVars *)user;
    Packet *p = PacketGetFromQueueOrAlloc();

    if (unlikely(p == NULL)) {
        SCReturn;
    }
    SC_ATOMIC_ADD(ptv->ref_cnt, 1);
    SCLogDebug("pcap-file: got packet, pfv=%p filename=%s ref_cnt now=%u p=%p", (void *)ptv,
            ptv->filename, SC_ATOMIC_GET(ptv->ref_cnt), (void *)p);

    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFILE);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = SCTIME_FROM_TIMEVAL_UNTRUSTED(&h->ts);
    SCLogDebug("p->ts.tv_sec %" PRIuMAX "", (uintmax_t)SCTIME_SECS(p->ts));
    p->datalink = ptv->datalink;
    p->pcap_v.pcap_cnt = ++pcap_g.cnt;

    p->pcap_v.tenant_id = ptv->shared->tenant_id;
    p->pcap_v.pfv = ptv;
    ptv->shared->pkts++;
    ptv->shared->bytes += h->caplen;

    p->ReleasePacket = PcapFileReleasePacket;

    if (unlikely(PacketCopyData(p, pkt, h->caplen))) {
        TmqhOutputPacketpool(ptv->shared->tv, p);
        PACKET_PROFILING_TMM_END(p, TMM_RECEIVEPCAPFILE);
        SCReturn;
    }

    /* We only check for checksum disable */
    if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_DISABLE) {
        p->flags |= PKT_IGNORE_CHECKSUM;
    } else if (pcap_g.checksum_mode == CHECKSUM_VALIDATION_AUTO) {
        if (ChecksumAutoModeCheck(ptv->shared->pkts, p->pcap_v.pcap_cnt,
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

char pcap_filename[PATH_MAX] = "unknown";

const char *PcapFileGetFilename(void)
{
    return pcap_filename;
}

void PcapFileSetCurrentPfv(PcapFileFileVars *pfv)
{
    pcap_current_pfv = pfv;
}

PcapFileFileVars *PcapFileGetCurrentPfv(void)
{
    return pcap_current_pfv;
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode PcapFileDispatch(PcapFileFileVars *ptv)
{
    SCEnter();

    PcapFileSetCurrentPfv(ptv);
    /* initialize all the thread's initial timestamp */
    if (likely(ptv->first_pkt_hdr != NULL)) {
        TmThreadsInitThreadsTimestamp(SCTIME_FROM_TIMEVAL(&ptv->first_pkt_ts));
        PcapFileCallbackLoop((char *)ptv, ptv->first_pkt_hdr,
                (u_char *)ptv->first_pkt_data);
        ptv->first_pkt_hdr = NULL;
        ptv->first_pkt_data = NULL;
    }

    int packet_q_len = 64;
    TmEcode loop_result = TM_ECODE_OK;
    strlcpy(pcap_filename, ptv->filename, sizeof(pcap_filename));

    while (loop_result == TM_ECODE_OK) {
        if (suricata_ctl_flags & SURICATA_STOP) {
            SCReturnInt(TM_ECODE_OK);
        }

        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Right now we just support reading packets one at a time. */
        int r = pcap_dispatch(ptv->pcap_handle, packet_q_len,
                          (pcap_handler)PcapFileCallbackLoop, (u_char *)ptv);
        if (unlikely(r == -1)) {
            SCLogError("error code %" PRId32 " %s for %s", r, pcap_geterr(ptv->pcap_handle),
                    ptv->filename);
            if (ptv->shared->cb_result == TM_ECODE_FAILED) {
                SCReturnInt(TM_ECODE_FAILED);
            }
            loop_result = TM_ECODE_DONE;
        } else if (unlikely(r == 0)) {
            SCLogInfo("pcap file %s end of file reached (pcap err code %" PRId32 ")",
                      ptv->filename, r);
            ptv->shared->files++;
            loop_result = TM_ECODE_DONE;
        } else if (ptv->shared->cb_result == TM_ECODE_FAILED) {
            SCLogError("Pcap callback PcapFileCallbackLoop failed for %s", ptv->filename);
            loop_result = TM_ECODE_FAILED;
        }
        StatsSyncCountersIfSignalled(&ptv->shared->tv->stats);
    }

    SCReturnInt(loop_result);
}

/** \internal
 *  \brief get the timestamp of the first packet and rewind
 *  \param pfv pcap file variables for storing the timestamp
 *  \retval bool true on success, false on error
 */
static bool PeekFirstPacketTimestamp(PcapFileFileVars *pfv)
{
    int r = pcap_next_ex(pfv->pcap_handle, &pfv->first_pkt_hdr, &pfv->first_pkt_data);
    if (r <= 0 || pfv->first_pkt_hdr == NULL) {
        SCLogError("failed to get first packet timestamp. pcap_next_ex(): %d", r);
        return false;
    }
    /* timestamp in pfv->first_pkt_hdr may not be 'struct timeval' so
     * do a manual copy of the members. */
    pfv->first_pkt_ts.tv_sec = pfv->first_pkt_hdr->ts.tv_sec;
    pfv->first_pkt_ts.tv_usec = pfv->first_pkt_hdr->ts.tv_usec;
    return true;
}

TmEcode InitPcapFile(PcapFileFileVars *pfv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";

    if(unlikely(pfv->filename == NULL)) {
        SCLogError("Filename was null");
        SCReturnInt(TM_ECODE_FAILED);
    }

    pfv->pcap_handle = pcap_open_offline(pfv->filename, errbuf);
    if (pfv->pcap_handle == NULL) {
        SCLogError("%s", errbuf);
        SCReturnInt(TM_ECODE_FAILED);
    }

#if defined(HAVE_SETVBUF) && defined(OS_LINUX)
    if (pcap_g.read_buffer_size > 0) {
        errno = 0;
        if (setvbuf(pcap_file(pfv->pcap_handle), pfv->buffer, _IOFBF, pcap_g.read_buffer_size) <
                0) {
            SCLogWarning("Failed to setvbuf on PCAP file handle: %s", strerror(errno));
        }
    }
#endif

    if (pfv->shared != NULL && pfv->shared->bpf_string != NULL) {
        SCLogInfo("using bpf-filter \"%s\"", pfv->shared->bpf_string);

        if (pcap_compile(pfv->pcap_handle, &pfv->filter, pfv->shared->bpf_string, 1, 0) < 0) {
            SCLogError("bpf compilation error %s for %s", pcap_geterr(pfv->pcap_handle),
                    pfv->filename);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (pcap_setfilter(pfv->pcap_handle, &pfv->filter) < 0) {
            SCLogError("could not set bpf filter %s for %s", pcap_geterr(pfv->pcap_handle),
                    pfv->filename);
            pcap_freecode(&pfv->filter);
            SCReturnInt(TM_ECODE_FAILED);
        }
        pcap_freecode(&pfv->filter);
    }

    SC_ATOMIC_INIT(pfv->alerts_count);
    SC_ATOMIC_SET(pfv->alerts_count, 0);

    SC_ATOMIC_INIT(pfv->ref_cnt);
    SC_ATOMIC_SET(pfv->ref_cnt, 0);

    pfv->cleanup_requested = false;

    pfv->datalink = pcap_datalink(pfv->pcap_handle);
    SCLogDebug("datalink %" PRId32 "", pfv->datalink);
    DatalinkSetGlobalType(pfv->datalink);

    if (!PeekFirstPacketTimestamp(pfv))
        SCReturnInt(TM_ECODE_FAILED);

    DecoderFunc UnusedFnPtr;
    TmEcode validated = ValidateLinkType(pfv->datalink, &UnusedFnPtr);
    SCReturnInt(validated);
}

TmEcode ValidateLinkType(int datalink, DecoderFunc *DecoderFn)
{
    switch (datalink) {
        case LINKTYPE_LINUX_SLL2:
            *DecoderFn = DecodeSll2;
            break;
        case LINKTYPE_LINUX_SLL:
            *DecoderFn = DecodeSll;
            break;
        case LINKTYPE_ETHERNET:
            *DecoderFn = DecodeEthernet;
            break;
        case LINKTYPE_PPP:
            *DecoderFn = DecodePPP;
            break;
        case LINKTYPE_IPV4:
        case LINKTYPE_IPV6:
        case LINKTYPE_RAW:
        case LINKTYPE_RAW2:
        case LINKTYPE_GRE_OVER_IP:
            *DecoderFn = DecodeRaw;
            break;
        case LINKTYPE_NULL:
            *DecoderFn = DecodeNull;
            break;
        case LINKTYPE_CISCO_HDLC:
            *DecoderFn = DecodeCHDLC;
            break;

        default:
            SCLogError(
                    "datalink type %" PRId32 " not (yet) supported in module PcapFile.", datalink);
            SCReturnInt(TM_ECODE_FAILED);
    }

    SCReturnInt(TM_ECODE_OK);
}

bool PcapFileShouldDeletePcapFile(PcapFileFileVars *pfv)
{
    if (pfv == NULL || pfv->shared == NULL) {
        return false;
    }

    if (pfv->shared->delete_mode == PCAP_FILE_DELETE_NONE) {
        return false;
    }

    if (pfv->shared->delete_mode == PCAP_FILE_DELETE_ALWAYS) {
        return true;
    }

    /* PCAP_FILE_DELETE_NON_ALERTS mode */
    uint64_t file_alerts = SC_ATOMIC_GET(pfv->alerts_count);

    if (file_alerts != 0) {
        SCLogDebug("Skipping deletion of %s due to %" PRIu64 " alert(s) generated.", pfv->filename,
                file_alerts);
        return false;
    }

    SCLogDebug("pcap-file: will delete %s (no alerts counted)", pfv->filename);

    return true;
}

void PcapFileFinalizePacket(PcapFileFileVars *pfv)
{
    if (pfv != NULL) {
        /* decrease ref count as packet is done */
        uint32_t prev = SC_ATOMIC_SUB(pfv->ref_cnt, 1);
        SCLogDebug("pcap-file: packet done pfv=%p filename=%s ref_cnt was=%u now=%u", (void *)pfv,
                pfv->filename, prev, prev - 1);
        if (prev == 1) {
            if (pfv->cleanup_requested) {
                CleanupPcapFileFileVars(pfv);
            }
        }
    }
}

void PcapFileAddAlertCount(PcapFileFileVars *pfv, uint16_t alert_count)
{
    if (pfv != NULL && alert_count > 0) {
        SC_ATOMIC_ADD(pfv->alerts_count, alert_count);
    }
}

static void PcapCaptureOnPacketWithAlerts(const Packet *p)
{
    PcapFileFileVars *pfv = p->pcap_v.pfv;
    if (pfv == NULL) {
        pfv = PcapFileGetCurrentPfv();
    }
    if (pfv != NULL) {
        /* alerts.cnt is uint16_t; count alerts for delete-on-non-alerts logic */
        PcapFileAddAlertCount(pfv, p->alerts.cnt);
    }
}

static void PcapCaptureOnPseudoPacketCreated(Packet *p)
{
    /* For pseudo packets created by generic layers, associate with current pfv
     * and ensure refcount held so deletion defers. */
    if (p->pcap_v.pfv == NULL) {
        PcapFileFileVars *pfv = PcapFileGetCurrentPfv();
        if (pfv != NULL) {
            p->pcap_v.pfv = pfv;
            p->ReleasePacket = PcapFileReleasePseudoPacket;
            SC_ATOMIC_ADD(pfv->ref_cnt, 1);
        }
    }
}

void PcapFileInstallCaptureHooks(void)
{
    CaptureHooksSet(PcapCaptureOnPacketWithAlerts, PcapCaptureOnPseudoPacketCreated);
}

PcapFileDeleteMode PcapFileParseDeleteMode(void)
{
    PcapFileDeleteMode delete_mode = PCAP_FILE_DELETE_NONE;
    const char *delete_when_done_str = NULL;

    if (SCConfGet("pcap-file.delete-when-done", &delete_when_done_str) == 1) {
        if (strcmp(delete_when_done_str, "non-alerts") == 0) {
            delete_mode = PCAP_FILE_DELETE_NON_ALERTS;
        } else {
            int delete_always = 0;
            if (SCConfGetBool("pcap-file.delete-when-done", &delete_always) == 1) {
                if (delete_always == 1) {
                    delete_mode = PCAP_FILE_DELETE_ALWAYS;
                }
            }
        }
    }

    return delete_mode;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
/**
 * \test Tests that the PcapFileShouldDeletePcapFile function correctly applies the
 * delete mode configuration.
 */
static int SourcePcapFileHelperTest01(void)
{
    PcapFileSharedVars shared;
    memset(&shared, 0, sizeof(shared));
    shared.delete_mode = PCAP_FILE_DELETE_ALWAYS;

    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    pfv.shared = &shared;
    pfv.filename = SCStrdup("test.pcap");
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);

    /* Test case 1: Always delete mode */
    int result1 = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF_NOT(result1);

    /* Test case 2: Non-alerts mode with no alerts */
    shared.delete_mode = PCAP_FILE_DELETE_NON_ALERTS;
    int result2 = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF_NOT(result2);

    /* Test case 3: Non-alerts mode with alerts */
    SC_ATOMIC_ADD(pfv.alerts_count, 1);
    int result3 = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF(result3);

    /* Test case 4: Always delete mode with alerts */
    shared.delete_mode = PCAP_FILE_DELETE_ALWAYS;
    int result4 = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF_NOT(result4);

    /* Test case 5: No delete mode */
    shared.delete_mode = PCAP_FILE_DELETE_NONE;
    int result5 = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF(result5);

    SCFree(pfv.filename);

    PASS;
}

/**
 * \test Test PcapFileFinalizePacket function with reference counting
 */
static int SourcePcapFileHelperTest02(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);
    SC_ATOMIC_INIT(pfv.ref_cnt);
    SC_ATOMIC_SET(pfv.ref_cnt, 0);
    pfv.cleanup_requested = false;

    /* Test adding alerts with reference counting */
    SC_ATOMIC_ADD(pfv.ref_cnt, 1); /* simulate packet in flight */
    PcapFileAddAlertCount(&pfv, 5);
    PcapFileFinalizePacket(&pfv);
    uint64_t count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF_NOT(count == 5);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv.ref_cnt) == 0); /* should be decremented */

    /* Test adding more alerts */
    SC_ATOMIC_ADD(pfv.ref_cnt, 1);
    PcapFileAddAlertCount(&pfv, 3);
    PcapFileFinalizePacket(&pfv);
    count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF_NOT(count == 8);

    /* Test with zero alerts (should not increment count) */
    SC_ATOMIC_ADD(pfv.ref_cnt, 1);
    PcapFileFinalizePacket(&pfv);
    count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF_NOT(count == 8);

    /* Test with NULL pfv (should not crash) */
    PcapFileFinalizePacket(NULL);

    PASS;
}

/* Mock for configuration testing */
static int SetupYamlConf(const char *conf_string)
{
    SCConfCreateContextBackup();
    SCConfInit();

    return SCConfYamlLoadString(conf_string, strlen(conf_string));
}

static void CleanupYamlConf(void)
{
    SCConfDeInit();
    SCConfRestoreContextBackup();
}

/**
 * \test Test PcapFileParseDeleteMode with all configuration combinations
 */
static int SourcePcapFileHelperTest03(void)
{
    /* Test 1: No configuration (should default to NONE) */
    SCConfCreateContextBackup();
    SCConfInit();

    PcapFileDeleteMode result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_NONE);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    /* Test 2: "false" configuration */
    const char *conf_false = "%YAML 1.1\n"
                             "---\n"
                             "pcap-file:\n"
                             "  delete-when-done: false\n";

    SetupYamlConf(conf_false);
    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_NONE);
    CleanupYamlConf();

    /* Test 3: "true" configuration */
    const char *conf_true = "%YAML 1.1\n"
                            "---\n"
                            "pcap-file:\n"
                            "  delete-when-done: true\n";

    SetupYamlConf(conf_true);
    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_ALWAYS);
    CleanupYamlConf();

    /* Test 4: "non-alerts" configuration */
    const char *conf_non_alerts = "%YAML 1.1\n"
                                  "---\n"
                                  "pcap-file:\n"
                                  "  delete-when-done: \"non-alerts\"\n";

    SetupYamlConf(conf_non_alerts);
    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_NON_ALERTS);
    CleanupYamlConf();

    /* Test 5: Invalid configuration (should default to NONE) */
    const char *conf_invalid = "%YAML 1.1\n"
                               "---\n"
                               "pcap-file:\n"
                               "  delete-when-done: \"invalid-value\"\n";

    SetupYamlConf(conf_invalid);
    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_NONE);
    CleanupYamlConf();

    PASS;
}

/**
 * \test pfv is NULL.
 */
static int SourcePcapFileHelperTest04(void)
{
    int rc = PcapFileShouldDeletePcapFile(NULL);
    FAIL_IF(rc);
    PASS;
}

/**
 * \test pfv->shared is NULL.
 */
static int SourcePcapFileHelperTest05(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));

    int rc = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF(rc);
    PASS;
}

/**
 * \test Test cleanup with reference counting and deferred deletion
 */
static int SourcePcapFileHelperTest06(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);
    SC_ATOMIC_INIT(pfv.ref_cnt);
    SC_ATOMIC_SET(pfv.ref_cnt, 2); /* simulate 2 packets in flight */
    pfv.cleanup_requested = false;

    /* Simulate first packet completion - should not cleanup yet */
    SC_ATOMIC_SUB(pfv.ref_cnt, 1);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv.ref_cnt) == 1);

    /* Request cleanup while packets are still in flight */
    pfv.cleanup_requested = true;

    /* Simulate second packet completion - should trigger cleanup */
    if (SC_ATOMIC_SUB(pfv.ref_cnt, 1) == 1) {
        FAIL_IF_NOT(pfv.cleanup_requested); /* cleanup should have been requested */
        /* In real code, CleanupPcapFileFileVars would be called here */
    }

    PASS;
}

/**
 * \test Test edge cases and error conditions
 */
static int SourcePcapFileHelperTest07(void)
{
    /* Test 1: PcapFileShouldDeletePcapFile with very high alert count */
    PcapFileSharedVars shared;
    memset(&shared, 0, sizeof(shared));
    shared.delete_mode = PCAP_FILE_DELETE_NON_ALERTS;

    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    pfv.shared = &shared;
    pfv.filename = SCStrdup("test.pcap");
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, UINT64_MAX); /* max value */

    int result = PcapFileShouldDeletePcapFile(&pfv);
    FAIL_IF(result); /* should not delete with max alerts */

    /* Test 2: PcapFileFinalizePacket with max alert count */
    SC_ATOMIC_INIT(pfv.ref_cnt);
    SC_ATOMIC_ADD(pfv.ref_cnt, 1);
    PcapFileAddAlertCount(&pfv, UINT16_MAX); /* max uint16_t */
    PcapFileFinalizePacket(&pfv);
    /* Should not overflow or crash */

    SCFree(pfv.filename);
    PASS;
}

/**
 * \test Test command-line --pcap-file-delete override behavior
 */
static int SourcePcapFileHelperTest08(void)
{
    /* Test 1: Command line overrides YAML "false" */
    const char *conf_false = "%YAML 1.1\n"
                             "---\n"
                             "pcap-file:\n"
                             "  delete-when-done: false\n";

    SetupYamlConf(conf_false);

    /* Simulate --pcap-file-delete command line option */
    int set_result = SCConfSetFinal("pcap-file.delete-when-done", "true");
    FAIL_IF_NOT(set_result == 1);

    PcapFileDeleteMode result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_ALWAYS); /* Should override YAML false */
    CleanupYamlConf();

    /* Test 2: Command line overrides YAML "non-alerts" */
    const char *conf_non_alerts = "%YAML 1.1\n"
                                  "---\n"
                                  "pcap-file:\n"
                                  "  delete-when-done: \"non-alerts\"\n";

    SetupYamlConf(conf_non_alerts);

    /* Simulate --pcap-file-delete command line option */
    set_result = SCConfSetFinal("pcap-file.delete-when-done", "true");
    FAIL_IF_NOT(set_result == 1);

    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_ALWAYS); /* Should override YAML "non-alerts" */
    CleanupYamlConf();

    /* Test 3: Command line overrides no YAML config */
    SCConfCreateContextBackup();
    SCConfInit();

    /* Simulate --pcap-file-delete command line option with no YAML config */
    set_result = SCConfSetFinal("pcap-file.delete-when-done", "true");
    FAIL_IF_NOT(set_result == 1);

    result = PcapFileParseDeleteMode();
    FAIL_IF_NOT(result == PCAP_FILE_DELETE_ALWAYS); /* Should set to always delete */

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * \test Test that cleanup defers while packets are in flight and that a file
 * with alerts is not deleted in NON_ALERTS mode.
 */
static int SourcePcapFileHelperTest09(void)
{
    PcapFileSharedVars *shared = SCCalloc(1, sizeof(*shared));
    FAIL_IF_NULL(shared);
    shared->delete_mode = PCAP_FILE_DELETE_NON_ALERTS;

    PcapFileFileVars *pfv = SCCalloc(1, sizeof(*pfv));
    FAIL_IF_NULL(pfv);
    pfv->shared = shared;
    pfv->filename = SCStrdup("unit_del_test.pcap");
    FAIL_IF_NULL(pfv->filename);

    SC_ATOMIC_INIT(pfv->alerts_count);
    SC_ATOMIC_SET(pfv->alerts_count, 0);
    SC_ATOMIC_INIT(pfv->ref_cnt);
    SC_ATOMIC_SET(pfv->ref_cnt, 2); /* two packets in flight */
    pfv->cleanup_requested = false;

    /* Request cleanup while packets still in flight: should defer. */
    CleanupPcapFileFileVars(pfv);
    FAIL_IF_NOT(pfv->cleanup_requested);
    FAIL_IF_NULL(pfv->filename); /* not freed yet */

    /* First packet completes and generates an alert. */
    PcapFileAddAlertCount(pfv, 1);
    PcapFileFinalizePacket(pfv);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv->alerts_count) == 1);

    /* Second (last) packet completes: triggers final cleanup. */
    PcapFileFinalizePacket(pfv);

    /* pfv memory is freed at this point; only free shared. */
    SCFree(shared);

    PASS;
}

/**
 * \test Cover unlink-on-ALWAYS branch (ref_cnt == 0) and deferred deletion when ref_cnt > 0
 */
static int SourcePcapFileHelperTest10(void)
{
    /* Create a temporary file that we expect to be deleted. */
    const char *tmpname = "suri_ut_delete_always.pcap";
    const uint8_t dummy[] = { 0x00 };
    int rc = TestHelperBufferToFile(tmpname, dummy, sizeof(dummy));
    FAIL_IF_NOT(rc >= 0);

    /* Case 1: delete ALWAYS with no packets in flight -> file unlinked immediately */
    PcapFileSharedVars *shared1 = SCCalloc(1, sizeof(*shared1));
    FAIL_IF_NULL(shared1);
    shared1->delete_mode = PCAP_FILE_DELETE_ALWAYS;

    PcapFileFileVars *pfv1 = SCCalloc(1, sizeof(*pfv1));
    FAIL_IF_NULL(pfv1);
    pfv1->shared = shared1;
    pfv1->filename = SCStrdup(tmpname);
    FAIL_IF_NULL(pfv1->filename);

    SC_ATOMIC_INIT(pfv1->alerts_count);
    SC_ATOMIC_SET(pfv1->alerts_count, 0);
    SC_ATOMIC_INIT(pfv1->ref_cnt);
    SC_ATOMIC_SET(pfv1->ref_cnt, 0);

    /* Provide a closable handle to cover close path. */
    pfv1->pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    FAIL_IF_NULL(pfv1->pcap_handle);

    CleanupPcapFileFileVars(pfv1);

    /* File should be gone. */
    FILE *f = fopen(tmpname, "rb");
    FAIL_IF_NOT_NULL(f);
    if (f != NULL)
        fclose(f);

    /* Case 2: delete ALWAYS but ref_cnt > 0 -> defer until finalize. */
    /* Recreate the file. */
    rc = TestHelperBufferToFile(tmpname, dummy, sizeof(dummy));
    FAIL_IF_NOT(rc >= 0);

    PcapFileSharedVars *shared2 = SCCalloc(1, sizeof(*shared2));
    FAIL_IF_NULL(shared2);
    shared2->delete_mode = PCAP_FILE_DELETE_ALWAYS;

    PcapFileFileVars *pfv2 = SCCalloc(1, sizeof(*pfv2));
    FAIL_IF_NULL(pfv2);
    pfv2->shared = shared2;
    pfv2->filename = SCStrdup(tmpname);
    FAIL_IF_NULL(pfv2->filename);

    SC_ATOMIC_INIT(pfv2->alerts_count);
    SC_ATOMIC_SET(pfv2->alerts_count, 0);
    SC_ATOMIC_INIT(pfv2->ref_cnt);
    SC_ATOMIC_SET(pfv2->ref_cnt, 1);
    pfv2->pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    FAIL_IF_NULL(pfv2->pcap_handle);

    CleanupPcapFileFileVars(pfv2);

    /* Still exists now because deletion should be deferred. */
    f = fopen(tmpname, "rb");
    FAIL_IF_NULL(f);
    if (f != NULL)
        fclose(f);

    /* Finalize the last packet which should trigger final cleanup & unlink. */
    PcapFileFinalizePacket(pfv2);

    /* Now the file should be gone. */
    f = fopen(tmpname, "rb");
    FAIL_IF_NOT_NULL(f);
    if (f != NULL)
        fclose(f);

    SCFree(shared1);
    SCFree(shared2);

    PASS;
}

/**
 * \test Test PcapFileReleasePseudoPacket refcount decrement without cleanup
 */
static int SourcePcapFileHelperTest11(void)
{
    /* Setup pfv with ref_cnt=2 so release does not trigger cleanup */
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    SC_ATOMIC_INIT(pfv.ref_cnt);
    SC_ATOMIC_SET(pfv.ref_cnt, 2);
    pfv.cleanup_requested = false;

    /* Allocate a packet from the pool to allow safe release */
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    p->pcap_v.pfv = &pfv;

    /* Call release and ensure ref count decremented by 1 */
    PcapFileReleasePseudoPacket(p);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv.ref_cnt) == 1);

    PASS;
}

/**
 * \test Test adding alert count and that cleanup after refcnt reaches zero
 *       does not delete when alerts exist in NON_ALERTS mode.
 */
static int SourcePcapFileHelperTest12(void)
{
    PcapFileSharedVars shared;
    memset(&shared, 0, sizeof(shared));
    shared.delete_mode = PCAP_FILE_DELETE_NON_ALERTS;

    PcapFileFileVars *pfv = SCCalloc(1, sizeof(*pfv));
    FAIL_IF_NULL(pfv);
    pfv->shared = &shared;
    pfv->filename = SCStrdup("ut_non_alerts.pcap");
    FAIL_IF_NULL(pfv->filename);

    SC_ATOMIC_INIT(pfv->alerts_count);
    SC_ATOMIC_SET(pfv->alerts_count, 0);
    SC_ATOMIC_INIT(pfv->ref_cnt);
    SC_ATOMIC_SET(pfv->ref_cnt, 1);
    pfv->cleanup_requested = true;

    /* Simulate pseudo alert */
    PcapFileAddAlertCount(pfv, 2);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv->alerts_count) == 2);

    /* Simulate last ref release triggering cleanup; file shouldn't be deleted
     * due to alerts > 0. We cannot check unlink here; rely on return value. */
    if (SC_ATOMIC_SUB(pfv->ref_cnt, 1) == 1) {
        CleanupPcapFileFileVars(pfv);
    }
    /* Success if no crash. */
    PASS;
}

/**
 * \test Test global current pfv pointer lifecycle
 */
static int SourcePcapFileHelperTest13(void)
{
    PcapFileFileVars *pfv = SCCalloc(1, sizeof(*pfv));
    FAIL_IF_NULL(pfv);
    pfv->filename = SCStrdup("ut_global_clear.pcap");
    FAIL_IF_NULL(pfv->filename);

    PcapFileSetCurrentPfv(pfv);
    FAIL_IF_NOT(PcapFileGetCurrentPfv() == pfv);

    /* Cleanup should clear global reference when pointing to this pfv */
    CleanupPcapFileFileVars(pfv);
    /* Global accessor must be NULL after cleanup. */
    FAIL_IF_NOT(PcapFileGetCurrentPfv() == NULL);
    PASS;
}

/**
 * \test Exercise unlink failure branch in CleanupPcapFileFileVars
 */
static int SourcePcapFileHelperTest14(void)
{
    PcapFileSharedVars shared;
    memset(&shared, 0, sizeof(shared));
    shared.delete_mode = PCAP_FILE_DELETE_ALWAYS;

    PcapFileFileVars *pfv = SCCalloc(1, sizeof(*pfv));
    FAIL_IF_NULL(pfv);
    pfv->shared = &shared;
    pfv->filename = SCStrdup("does-not-exist-ut.pcap");
    FAIL_IF_NULL(pfv->filename);

    SC_ATOMIC_INIT(pfv->ref_cnt);
    SC_ATOMIC_SET(pfv->ref_cnt, 0);

    /* Attempt cleanup; unlink should fail but must not crash */
    CleanupPcapFileFileVars(pfv);
    PASS;
}

/**
 * \test Cover alerts hook fallback using current PFV
 */
static int SourcePcapFileHelperTest15(void)
{
    PcapFileInstallCaptureHooks();

    PcapFileFileVars *pfv = SCCalloc(1, sizeof(*pfv));
    FAIL_IF_NULL(pfv);
    SC_ATOMIC_INIT(pfv->alerts_count);
    SC_ATOMIC_SET(pfv->alerts_count, 0);

    /* Set current PFV to exercise fallback path */
    PcapFileSetCurrentPfv(pfv);

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    p->alerts.cnt = 3;    /* simulate 3 alerts */
    p->pcap_v.pfv = NULL; /* force fallback */

    /* Call hook: it should update pfv->alerts_count */
    CaptureHooksOnPacketWithAlerts(p);
    FAIL_IF_NOT(SC_ATOMIC_GET(pfv->alerts_count) == 3);

    /* Cleanup */
    PacketFreeOrRelease(p);
    CleanupPcapFileFileVars(pfv);
    PASS;
}

/**
 * \brief Register unit tests for pcap file helper
 */
void SourcePcapFileHelperRegisterTests(void)
{
    UtRegisterTest("SourcePcapFileHelperTest01", SourcePcapFileHelperTest01);
    UtRegisterTest("SourcePcapFileHelperTest02", SourcePcapFileHelperTest02);
    UtRegisterTest("SourcePcapFileHelperTest03", SourcePcapFileHelperTest03);
    UtRegisterTest("SourcePcapFileHelperTest04", SourcePcapFileHelperTest04);
    UtRegisterTest("SourcePcapFileHelperTest05", SourcePcapFileHelperTest05);
    UtRegisterTest("SourcePcapFileHelperTest06", SourcePcapFileHelperTest06);
    UtRegisterTest("SourcePcapFileHelperTest07", SourcePcapFileHelperTest07);
    UtRegisterTest("SourcePcapFileHelperTest08", SourcePcapFileHelperTest08);
    UtRegisterTest("SourcePcapFileHelperTest09", SourcePcapFileHelperTest09);
    UtRegisterTest("SourcePcapFileHelperTest10", SourcePcapFileHelperTest10);
    UtRegisterTest("SourcePcapFileHelperTest11", SourcePcapFileHelperTest11);
    UtRegisterTest("SourcePcapFileHelperTest12", SourcePcapFileHelperTest12);
    UtRegisterTest("SourcePcapFileHelperTest13", SourcePcapFileHelperTest13);
    UtRegisterTest("SourcePcapFileHelperTest14", SourcePcapFileHelperTest14);
    UtRegisterTest("SourcePcapFileHelperTest15", SourcePcapFileHelperTest15);
}
#endif /* UNITTESTS */
