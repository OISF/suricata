/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */

#include "suricata-common.h"
#include "source-pcap-file.h"
#include "detect-engine.h"
#include "util-classification-config.h"
#include "util-reference-config.h"
#include "app-layer.h"
#include "tm-queuehandlers.h"
#include "util-cidr.h"
#include "util-proto-name.h"
#include "detect-engine-tag.h"
#include "detect-engine-threshold.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "app-layer-htp.h"
#include "detect-fast-pattern.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"
#include "pkt-var.h"
#include "flow-util.h"

#include <fuzz_pcap.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;
ThreadVars tv;
DecodeThreadVars *dtv;
// FlowWorkerThreadData
void *fwd;
SCInstance surifuzz;

#include "confyaml.c"

static void SigGenereateAware(const uint8_t *data, size_t size, char *r, size_t *len)
{
    *len = snprintf(r, 511, "alert ip any any -> any any (");
    for (size_t i = 0; i + 1 < size && *len < 511; i++) {
        if (data[i] & 0x80) {
            size_t off = (data[i] & 0x7F + ((data[i + 1] & 0xF) << 7)) %
                         (sizeof(sigmatch_table) / sizeof(SigTableElmt));
            if (sigmatch_table[off].flags & SIGMATCH_NOOPT ||
                    ((data[i + 1] & 0x80) && sigmatch_table[off].flags & SIGMATCH_OPTIONAL_OPT)) {
                *len += snprintf(r + *len, 511 - *len, "; %s;", sigmatch_table[off].name);
            } else {
                *len += snprintf(r + *len, 511 - *len, "; %s:", sigmatch_table[off].name);
            }
            i++;
        } else {
            r[*len] = data[i];
            *len = *len + 1;
        }
    }
    if (*len < 511) {
        *len += snprintf(r + *len, 511 - *len, ")");
    } else {
        r[511] = 0;
        *len = 511;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FPC_buffer_t pkts;
    const u_char *pkt;
    struct pcap_pkthdr header;
    int r;
    Packet *p;
    size_t pos;
    size_t pcap_cnt = 0;

    if (initialized == 0) {
        // Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        GlobalsInitPreConfig();
        run_mode = RUNMODE_PCAP_FILE;
        // redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        // disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        // do not load rules before reproducible DetectEngineReload
        remove("/tmp/fuzz.rules");
        surifuzz.sig_file = strdup("/tmp/fuzz.rules");
        surifuzz.sig_file_exclusive = 1;
        // loads rules after init
        surifuzz.delayed_detect = 1;

        PostConfLoadedSetup(&surifuzz);
        PreRunPostPrivsDropInit(run_mode);
        PostConfLoadedDetectSetup(&surifuzz);

        memset(&tv, 0, sizeof(tv));
        tv.flow_queue = FlowQueueNew();
        if (tv.flow_queue == NULL)
            abort();
        dtv = DecodeThreadVarsAlloc(&tv);
        DecodeRegisterPerfCounters(dtv, &tv);
        tmm_modules[TMM_FLOWWORKER].ThreadInit(&tv, NULL, &fwd);
        StatsSetupPrivate(&tv);

        extern intmax_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();
        initialized = 1;
    }

    if (size < 1 + FPC0_HEADER_LEN) {
        return 0;
    }
    for (pos = 0; pos < size - FPC0_HEADER_LEN; pos++) {
        if (data[pos] == 0) {
            break;
        }
    }
    // initialize FPC with the buffer
    if (FPC_init(&pkts, data + pos + 1, size - pos - 1) < 0) {
        return 0;
    }

    // dump signatures to a file so as to reuse SigLoadSignatures
    char sigaware[512];
    size_t len;
    SigGenereateAware(data, pos + 1, sigaware, &len);
    if (TestHelperBufferToFile(surifuzz.sig_file, (uint8_t *)sigaware, len) < 0) {
        return 0;
    }

    if (DetectEngineReload(&surifuzz) < 0) {
        return 0;
    }
    DetectEngineThreadCtx *old_det_ctx = FlowWorkerGetDetectCtxPtr(fwd);

    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    de_ctx->ref_cnt--;
    DetectEngineThreadCtx *new_det_ctx = DetectEngineThreadCtxInitForReload(&tv, de_ctx, 1);
    FlowWorkerReplaceDetectCtx(fwd, new_det_ctx);

    DetectEngineThreadCtxDeinit(NULL, old_det_ctx);

    // loop over packets
    r = FPC_next(&pkts, &header, &pkt);
    p = PacketGetFromAlloc();
    p->ts.tv_sec = header.ts.tv_sec;
    p->ts.tv_usec = header.ts.tv_usec;
    p->datalink = pkts.datalink;
    while (r > 0) {
        if (PacketCopyData(p, pkt, header.caplen) == 0) {
            // DecodePcapFile
            TmEcode ecode = tmm_modules[TMM_DECODEPCAPFILE].Func(&tv, p, dtv);
            if (ecode == TM_ECODE_FAILED) {
                break;
            }
            Packet *extra_p = PacketDequeueNoLock(&tv.decode_pq);
            while (extra_p != NULL) {
                PacketFreeOrRelease(extra_p);
                extra_p = PacketDequeueNoLock(&tv.decode_pq);
            }
            tmm_modules[TMM_FLOWWORKER].Func(&tv, p, fwd);
            extra_p = PacketDequeueNoLock(&tv.decode_pq);
            while (extra_p != NULL) {
                PacketFreeOrRelease(extra_p);
                extra_p = PacketDequeueNoLock(&tv.decode_pq);
            }
        }
        r = FPC_next(&pkts, &header, &pkt);
        PACKET_RECYCLE(p);
        p->ts.tv_sec = header.ts.tv_sec;
        p->ts.tv_usec = header.ts.tv_usec;
        p->datalink = pkts.datalink;
        pcap_cnt++;
        p->pcap_cnt = pcap_cnt;
    }
    PacketFree(p);
    FlowReset();

    return 0;
}
