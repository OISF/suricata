/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for predefined signatures and pcap (aware)
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
#include "tm-modules.h"
#include "tmqh-packetpool.h"
#include "util-conf.h"
#include "packet.h"

#include <fuzz_pcap.h>

int LLVMFuzzerInitialize(const int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;
ThreadVars tv;
DecodeThreadVars *dtv;
// FlowWorkerThreadData
void *fwd;
SCInstance surifuzz;

#include "confyaml.c"

char *filepath = NULL;

int LLVMFuzzerInitialize(const int *argc, char ***argv)
{
    filepath = dirname(strdup((*argv)[0]));
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FPC_buffer_t pkts;
    const u_char *pkt;
    struct pcap_pkthdr header;
    int r;
    Packet *p;
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
        surifuzz.sig_file = malloc(strlen(filepath) + strlen("/fuzz.rules") + 1);
        memcpy(surifuzz.sig_file, filepath, strlen(filepath));
        memcpy(surifuzz.sig_file + strlen(filepath), "/fuzz.rules", strlen("/fuzz.rules"));
        surifuzz.sig_file[strlen(filepath) + strlen("/fuzz.rules")] = 0;
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
        if (DetectEngineReload(&surifuzz) < 0) {
            return 0;
        }

        initialized = 1;
    }

    if (size < FPC0_HEADER_LEN) {
        return 0;
    }
    // initialize FPC with the buffer
    if (FPC_init(&pkts, data, size) < 0) {
        return 0;
    }

    // loop over packets
    r = FPC_next(&pkts, &header, &pkt);
    p = PacketGetFromAlloc();
    p->ts.tv_sec = header.ts.tv_sec;
    p->ts.tv_usec = header.ts.tv_usec % 1000000;
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
        PacketRecycle(p);
        p->ts.tv_sec = header.ts.tv_sec;
        p->ts.tv_usec = header.ts.tv_usec % 1000000;
        p->datalink = pkts.datalink;
        pcap_cnt++;
        p->pcap_cnt = pcap_cnt;
    }
    PacketFree(p);
    FlowReset();

    return 0;
}
