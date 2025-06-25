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
#include "source-pcap-file.h"
#include "util-exception-policy.h"
#include "conf-yaml-loader.h"

extern uint32_t max_pending_packets;
extern PcapFileGlobalVars pcap_g;

static void PcapFileCallbackLoop(char *user, struct pcap_pkthdr *h, u_char *pkt);

static void PcapFileReleasePacket(Packet *p)
{
    PcapFileFileVars *pfv = p->pcap_v.pfv;
    if (pfv != NULL) {
        PcapFileAddAlerts(pfv, p->alerts.cnt);
    }

    PacketFreeOrRelease(p);
}

void CleanupPcapFileFileVars(PcapFileFileVars *pfv)
{
    if (pfv != NULL) {
        if (pfv->pcap_handle != NULL) {
            pcap_close(pfv->pcap_handle);
            pfv->pcap_handle = NULL;
        }
        if (pfv->filename != NULL) {
            if (ShouldDeletePcapFile(pfv)) {
                SCLogDebug("Deleting pcap file %s", pfv->filename);
                if (unlink(pfv->filename) != 0) {
                    SCLogWarning("Failed to delete %s: %s", pfv->filename, strerror(errno));
                }
            }
            SCFree(pfv->filename);
            pfv->filename = NULL;
        }
        pfv->shared = NULL;
        SCFree(pfv);
    }
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
    PACKET_PROFILING_TMM_START(p, TMM_RECEIVEPCAPFILE);

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts = SCTIME_FROM_TIMEVAL_UNTRUSTED(&h->ts);
    SCLogDebug("p->ts.tv_sec %" PRIuMAX "", (uintmax_t)SCTIME_SECS(p->ts));
    p->datalink = ptv->datalink;
    p->pcap_cnt = ++pcap_g.cnt;

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

char pcap_filename[PATH_MAX] = "unknown";

const char *PcapFileGetFilename(void)
{
    return pcap_filename;
}

/**
 *  \brief Main PCAP file reading Loop function
 */
TmEcode PcapFileDispatch(PcapFileFileVars *ptv)
{
    SCEnter();

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
        StatsSyncCountersIfSignalled(ptv->shared->tv);
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

bool ShouldDeletePcapFile(PcapFileFileVars *pfv)
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

    return true;
}

void PcapFileAddAlerts(PcapFileFileVars *pfv, uint16_t alert_count)
{
    if (pfv != NULL && alert_count > 0) {
        SC_ATOMIC_ADD(pfv->alerts_count, alert_count);
    }
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
/**
 * \test Tests that the ShouldDeletePcapFile function correctly applies the
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
    int result1 = ShouldDeletePcapFile(&pfv);
    FAIL_IF(result1 != true);

    /* Test case 2: Non-alerts mode with no alerts */
    shared.delete_mode = PCAP_FILE_DELETE_NON_ALERTS;
    int result2 = ShouldDeletePcapFile(&pfv);
    FAIL_IF(result2 != true);

    /* Test case 3: Non-alerts mode with alerts */
    SC_ATOMIC_ADD(pfv.alerts_count, 1);
    int result3 = ShouldDeletePcapFile(&pfv);
    FAIL_IF(result3 != false);

    /* Test case 4: Always delete mode with alerts */
    shared.delete_mode = PCAP_FILE_DELETE_ALWAYS;
    int result4 = ShouldDeletePcapFile(&pfv);
    FAIL_IF(result4 != true);

    /* Test case 5: No delete mode */
    shared.delete_mode = PCAP_FILE_DELETE_NONE;
    int result5 = ShouldDeletePcapFile(&pfv);
    FAIL_IF(result5 != false);

    SCFree(pfv.filename);

    PASS;
}

/**
 * \test Test that alert counters are properly incremented
 */
static int SourcePcapFileHelperTest02(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);

    Packet p;
    memset(&p, 0, sizeof(p));

    /* first batch */
    p.alerts.cnt = 2;
    SC_ATOMIC_ADD(pfv.alerts_count, p.alerts.cnt);
    uint64_t alerts_count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF(alerts_count != 2);

    /* second batch */
    p.alerts.cnt = 3;
    SC_ATOMIC_ADD(pfv.alerts_count, p.alerts.cnt);
    alerts_count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF(alerts_count != 5);

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
 * \test Test that configuration is properly parsed
 */
static int SourcePcapFileHelperTest03(void)
{
    const char *delete_when_done_str = NULL;

    const char *conf_string = "%YAML 1.1\n"
                              "---\n"
                              "pcap-file:\n"
                              "  delete-when-done: non-alerts\n";

    SetupYamlConf(conf_string);

    int result = SCConfGet("pcap-file.delete-when-done", &delete_when_done_str);
    FAIL_IF(result != 1);
    FAIL_IF(strcmp(delete_when_done_str, "non-alerts") != 0);

    CleanupYamlConf();

    const char *conf_string2 = "%YAML 1.1\n"
                               "---\n"
                               "pcap-file:\n"
                               "  delete-when-done: true\n";

    SetupYamlConf(conf_string2);

    int delete_always = 0;
    result = SCConfGetBool("pcap-file.delete-when-done", &delete_always);
    FAIL_IF(result != 1);
    FAIL_IF(delete_always != 1);

    CleanupYamlConf();

    PASS;
}

/**
 * \test pfv is NULL.
 */
static int SourcePcapFileHelperTest04(void)
{
    int rc = ShouldDeletePcapFile(NULL);
    FAIL_IF(rc != false);
    PASS;
}

/**
 * \test pfv->shared is NULL.
 */
static int SourcePcapFileHelperTest05(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));

    int rc = ShouldDeletePcapFile(&pfv);
    FAIL_IF(rc != false);
    PASS;
}

static int SourcePcapFileHelperTest06(void)
{
    PcapFileSharedVars shared;
    memset(&shared, 0, sizeof(shared));
    shared.delete_mode = PCAP_FILE_DELETE_NONE;

    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    pfv.shared = &shared;
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);

    int rc = ShouldDeletePcapFile(&pfv);
    FAIL_IF(rc != false);
    PASS;
}

/**
 * \test Test PcapFileAddAlerts function directly
 */
static int SourcePcapFileHelperTest07(void)
{
    PcapFileFileVars pfv;
    memset(&pfv, 0, sizeof(pfv));
    SC_ATOMIC_INIT(pfv.alerts_count);
    SC_ATOMIC_SET(pfv.alerts_count, 0);

    /* Test adding alerts */
    PcapFileAddAlerts(&pfv, 5);
    uint64_t count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF(count != 5);

    /* Test adding more alerts */
    PcapFileAddAlerts(&pfv, 3);
    count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF(count != 8);

    /* Test with zero alerts (should not increment) */
    PcapFileAddAlerts(&pfv, 0);
    count = SC_ATOMIC_GET(pfv.alerts_count);
    FAIL_IF(count != 8);

    /* Test with NULL pfv (should not crash) */
    PcapFileAddAlerts(NULL, 10);

    PASS;
}

/**
 * \test Test command line --pcap-file-delete override behavior
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
    FAIL_IF(set_result != 1);

    PcapFileDeleteMode result = PcapFileParseDeleteMode();
    FAIL_IF(result != PCAP_FILE_DELETE_ALWAYS); /* Should override YAML false */
    CleanupYamlConf();

    /* Test 2: Command line overrides YAML "non-alerts" */
    const char *conf_non_alerts = "%YAML 1.1\n"
                                  "---\n"
                                  "pcap-file:\n"
                                  "  delete-when-done: \"non-alerts\"\n";

    SetupYamlConf(conf_non_alerts);

    /* Simulate --pcap-file-delete command line option */
    set_result = SCConfSetFinal("pcap-file.delete-when-done", "true");
    FAIL_IF(set_result != 1);

    result = PcapFileParseDeleteMode();
    FAIL_IF(result != PCAP_FILE_DELETE_ALWAYS); /* Should override YAML "non-alerts" */
    CleanupYamlConf();

    /* Test 3: Command line overrides no YAML config */
    SCConfCreateContextBackup();
    SCConfInit();

    /* Simulate --pcap-file-delete command line option with no YAML config */
    set_result = SCConfSetFinal("pcap-file.delete-when-done", "true");
    FAIL_IF(set_result != 1);

    result = PcapFileParseDeleteMode();
    FAIL_IF(result != PCAP_FILE_DELETE_ALWAYS); /* Should set to always delete */

    SCConfDeInit();
    SCConfRestoreContextBackup();

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
}
#endif /* UNITTESTS */
