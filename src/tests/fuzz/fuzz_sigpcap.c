/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include <pcap/pcap.h>

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
#include "util-decode-asn1.h"
#include "detect-fast-pattern.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static int initialized = 0;
ThreadVars tv;
PacketQueue pq;
DecodeThreadVars *dtv;
//FlowWorkerThreadData
void *fwd;

const char configNoChecksum[] = "\
%YAML 1.1\n\
---\n\
pcap-file:\n\
\n\
  checksum-checks: no\n\
\n\
stream:\n\
\n\
checksum-validation: no\n\
";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    int r;
    Packet *p;
    size_t pos;

    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();

        run_mode = RUNMODE_PCAP_FILE;
        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum));
        suricata.sig_file = strdup("/tmp/fuzz.rules");
        suricata.sig_file_exclusive = 1;
        //loads rules after init
        suricata.delayed_detect = 1;

        SupportFastPatternForSigMatchTypes();
        PostConfLoadedSetup(&suricata);

        //dummy init before DetectEngineReload
        DetectEngineCtx * de_ctx = DetectEngineCtxInit();
        DetectEngineAddToMaster(de_ctx);

        memset(&tv, 0, sizeof(tv));
        dtv = DecodeThreadVarsAlloc(&tv);
        DecodeRegisterPerfCounters(dtv, &tv);
        memset(&pq, 0, sizeof(pq));
        tmm_modules[TMM_FLOWWORKER].ThreadInit(&tv, NULL, &fwd);
        StatsSetupPrivate(&tv);

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
        if (UTHbufferToFile(suricata.sig_file, data, pos-1) < 0) {
            return 0;
        }
    } else {
        if (UTHbufferToFile(suricata.sig_file, data, pos) < 0) {
            return 0;
        }
    }

    if (DetectEngineReload(&suricata) < 0) {
        return 0;
    }
    if (pos < size) {
        //skip zero
        pos++;
    }
    data += pos;
    size -= pos;

    //rewrite buffer to a file as libpcap does not have buffer inputs
    if (UTHbufferToFile("/tmp/fuzz.pcap", data, size) < 0) {
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
    p->datalink = pcap_datalink(pkts);
    while (r > 0) {
        PacketCopyData(p, pkt, header->caplen);
        //DecodePcapFile
        tmm_modules[TMM_DECODEPCAPFILE].Func(&tv, p, dtv, &pq, NULL);
        //TODO tmm_modules worker
        Packet *extra_p = PacketDequeue(&pq);
        while (extra_p != NULL) {
            PacketFree(extra_p);
            extra_p = PacketDequeue(&pq);
        }
        tmm_modules[TMM_FLOWWORKER].Func(&tv, p, fwd, &pq, NULL);
        extra_p = PacketDequeue(&pq);
        while (extra_p != NULL) {
            PacketFree(extra_p);
            extra_p = PacketDequeue(&pq);
        }
        r = pcap_next_ex(pkts, &header, &pkt);
    }
    //close structure
    pcap_close(pkts);
    PacketFree(p);

    return 0;
}
