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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


static int initialized = 0;
ThreadVars tv;
DecodeThreadVars *dtv;
//FlowWorkerThreadData
void *fwd;
SCInstance surifuzz;

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
outputs:\n\
  - fast:\n\
      enabled: yes\n\
      filename: /dev/null\n\
  - eve-log:\n\
      enabled: yes\n\
      filetype: regular\n\
      filename: /dev/null\n\
      xff:\n\
        enabled: yes\n\
        mode: extra-data\n\
        deployment: reverse\n\
        header: X-Forwarded-For\n\
      types:\n\
        - alert:\n\
            payload: yes\n\
            payload-printable: yes\n\
            packet: yes\n\
            metadata: yes\n\
            http-body: yes\n\
            http-body-printable: yes\n\
            tagged-packets: yes\n\
        - anomaly:\n\
            enabled: yes\n\
            types:\n\
              decode: yes\n\
              stream: yes\n\
              applayer: yes\n\
            packethdr: yes\n\
        - http:\n\
            extended: yes\n\
            dump-all-headers: both\n\
        - dns\n\
        - tls:\n\
            extended: yes\n\
            session-resumption: yes\n\
        - files\n\
        - smtp:\n\
            extended: yes\n\
        - dnp3\n\
        - ftp\n\
        - rdp\n\
        - nfs\n\
        - smb\n\
        - tftp\n\
        - ikev2\n\
        - krb5\n\
        - snmp\n\
        - rfb\n\
        - sip\n\
        - dhcp:\n\
            enabled: yes\n\
            extended: yes\n\
        - ssh\n\
        - flow\n\
        - netflow\n\
        - metadata\n\
  - http-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
  - tls-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
app-layer:\n\
  protocols:\n\
    rdp:\n\
      enabled: yes\n\
    modbus:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 502\n\
    dnp3:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 20000\n\
    enip:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 44818\n\
        sp: 44818\n\
    sip:\n\
      enabled: yes\n\
    ssh:\n\
      enabled: yes\n\
      hassh: yes\n\
";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
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

        GlobalsInitPreConfig();
        run_mode = RUNMODE_PCAP_FILE;
        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }
        surifuzz.sig_file = strdup("/tmp/fuzz.rules");
        surifuzz.sig_file_exclusive = 1;
        //loads rules after init
        surifuzz.delayed_detect = 1;

        PostConfLoadedSetup(&surifuzz);
        PreRunPostPrivsDropInit(run_mode);
        PostConfLoadedDetectSetup(&surifuzz);

        memset(&tv, 0, sizeof(tv));
        dtv = DecodeThreadVarsAlloc(&tv);
        DecodeRegisterPerfCounters(dtv, &tv);
        tmm_modules[TMM_FLOWWORKER].ThreadInit(&tv, NULL, &fwd);
        StatsSetupPrivate(&tv);

        PacketPoolInitEmpty();
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
    p->datalink = pcap_datalink(pkts);
    while (r > 0) {
        PacketCopyData(p, pkt, header->caplen);
        //DecodePcapFile
        TmEcode ecode = tmm_modules[TMM_DECODEPCAPFILE].Func(&tv, p, dtv);
        if (ecode == TM_ECODE_FAILED) {
            break;
        }
        Packet *extra_p = PacketDequeueNoLock(&tv.decode_pq);
        while (extra_p != NULL) {
            PacketFree(extra_p);
            extra_p = PacketDequeueNoLock(&tv.decode_pq);
        }
        tmm_modules[TMM_FLOWWORKER].Func(&tv, p, fwd);
        extra_p = PacketDequeueNoLock(&tv.decode_pq);
        while (extra_p != NULL) {
            PacketFree(extra_p);
            extra_p = PacketDequeueNoLock(&tv.decode_pq);
        }
        r = pcap_next_ex(pkts, &header, &pkt);
        PACKET_RECYCLE(p);
    }
    //close structure
    pcap_close(pkts);
    PacketFree(p);

    return 0;
}
