/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for AppLayerProtoDetectGetProto
 */


#include <pcap/pcap.h>

#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "defrag.h"
#include "tm-modules.h"
#include "source-pcap-file.h"


void fuzz_openFile(const char * name) {
}

static int bufferToFile(const char * name, const uint8_t *Data, size_t Size) {
    FILE * fd;
    if (remove(name) != 0) {
        if (errno != ENOENT) {
            printf("failed remove, errno=%d\n", errno);
            return -1;
        }
    }
    fd = fopen(name, "wb");
    if (fd == NULL) {
        printf("failed open, errno=%d\n", errno);
        return -2;
    }
    if (fwrite (Data, 1, Size, fd) != Size) {
        fclose(fd);
        return -3;
    }
    fclose(fd);
    return 0;
}

static int initialized = 0;
ThreadVars tv;
PacketQueue pq;
DecodeThreadVars *dtv;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    int r;
    Packet *p;

    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();
        run_mode = RUNMODE_UNITTEST;

        //TODO put in global init ?
        MpmTableSetup();
        SpmTableSetup();
        AppLayerProtoDetectSetup();
        DefragInit();
        FlowInitConfig(FLOW_QUIET);

        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        suricata.checksum_validation = 0;

        TmModuleDecodePcapFileRegister();

        memset(&tv, 0, sizeof(tv));
        dtv = DecodeThreadVarsAlloc(&tv);
        DecodeRegisterPerfCounters(dtv, &tv);
        StatsSetupPrivate(&tv);
        memset(&pq, 0, sizeof(pq));

        initialized = 1;
    }

    //rewrite buffer to a file as libpcap does not have buffer inputs
    if (bufferToFile("/tmp/fuzz.pcap", data, size) < 0) {
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
        PacketSetData(p, pkt, header->caplen);
        //DecodePcapFile
        tmm_modules[TMM_DECODEPCAPFILE].Func(&tv, p, dtv, &pq, NULL);
        Packet *extra_p = PacketDequeue(&pq);
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
