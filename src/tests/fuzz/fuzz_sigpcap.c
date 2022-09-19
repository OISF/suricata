/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for signature file and pcap file
 */

#include "suricata-common.h"
#include "source-pcap-file.h"
#include "detect-engine.h"
#include "util-classification-config.h"
#include "util-reference-config.h"
#include "app-layer.h"
#include "tm-queuehandlers.h"
#include "util-cidr.h"
#include "util-profiling.h"
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
#include "flow-worker.h"
#include "tm-modules.h"
#include "tmqh-packetpool.h"
#include "util-file.h"
#include "util-conf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static int initialized = 0;
ThreadVars tv;
DecodeThreadVars *dtv;
//FlowWorkerThreadData
void *fwd;
SCInstance surifuzz;

#include "confyaml.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    int r;
    Packet *p;
    size_t pos;
    size_t pcap_cnt = 0;

    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        GlobalsInitPreConfig();
        run_mode = RUNMODE_PCAP_FILE;
        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        // do not load rules before reproducible DetectEngineReload
        remove("/tmp/fuzz.rules");
        surifuzz.sig_file = strdup("/tmp/fuzz.rules");
        surifuzz.sig_file_exclusive = 1;
        //loads rules after init
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

    /* TODO add yaml config
     for (pos = 0; pos < size; pos++) {
        if (data[pos] == 0) {
            break;
        }
    }
    if (ConfYamlLoadString(data, pos) != 0) {
        return 0;
    }
    if (pos < size) {
        //skip zero
        pos++;
    }
    data += pos;
    size -= pos;*/

    for (pos=0; pos < size; pos++) {
        if (data[pos] == 0) {
            break;
        }
    }
    if (pos > 0 && pos < size) {
        // dump signatures to a file so as to reuse SigLoadSignatures
        if (TestHelperBufferToFile(surifuzz.sig_file, data, pos-1) < 0) {
            return 0;
        }
    } else {
        if (TestHelperBufferToFile(surifuzz.sig_file, data, pos) < 0) {
            return 0;
        }
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

    if (pos < size) {
        //skip zero
        pos++;
    }
    data += pos;
    size -= pos;

    //rewrite buffer to a file as libpcap does not have buffer inputs
    if (TestHelperBufferToFile("/tmp/fuzz.pcap", data, size) < 0) {
        return 0;
    }

    //initialize structure
    pkts = pcap_open_offline("/tmp/fuzz.pcap", errbuf);
    if (pkts == NULL) {
        return 0;
    }

    //loop over packets
    r = pcap_next_ex(pkts, &header, &pkt);
    p = PacketGetFromAlloc();
    p->ts.tv_sec = header->ts.tv_sec;
    p->ts.tv_usec = header->ts.tv_usec % 1000000;
    p->datalink = pcap_datalink(pkts);
    while (r > 0) {
        if (PacketCopyData(p, pkt, header->caplen) == 0) {
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
        r = pcap_next_ex(pkts, &header, &pkt);
        PacketRecycle(p);
        p->ts.tv_sec = header->ts.tv_sec;
        p->ts.tv_usec = header->ts.tv_usec % 1000000;
        p->datalink = pcap_datalink(pkts);
        pcap_cnt++;
        p->pcap_cnt = pcap_cnt;
    }
    //close structure
    pcap_close(pkts);
    PacketFree(p);
    FlowReset();

    return 0;
}
