/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz target for TMM_DECODEPCAPFILE
 */

#include "suricata-common.h"
#include "suricata.h"
#include "app-layer-detect-proto.h"
#include "defrag.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "source-pcap-file.h"
#include "util-unittest-helper.h"
#include "conf-yaml-loader.h"
#include "util-time.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int initialized = 0;
SCInstance surifuzz;

const char configNoChecksum[] = "\
%YAML 1.1\n\
---\n\
pcap-file:\n\
\n\
  checksum-checks: no\n\
";

ThreadVars *tv;
DecodeThreadVars *dtv;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    void *ptv = NULL;

    if (initialized == 0) {
        //Redirects logs to /dev/null
        setenv("SC_LOG_OP_IFACE", "file", 0);
        setenv("SC_LOG_FILE", "/dev/null", 0);

        InitGlobal();
        run_mode = RUNMODE_PCAP_FILE;

        //redirect logs to /tmp
        ConfigSetLogDirectory("/tmp/");
        //disables checksums validation for fuzzing
        if (ConfYamlLoadString(configNoChecksum, strlen(configNoChecksum)) != 0) {
            abort();
        }

        PostConfLoadedSetup(&surifuzz);

        RunModeInitialize();
        TimeModeSetOffline();
        PcapFileGlobalInit();

        tv = TmThreadCreatePacketHandler("fuzz",
                                         "packetpool", "packetpool",
                                         "packetpool", "packetpool",
                                         "pktacqloop");
        if (tv == NULL) {
            return 0;
        }
        TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
        if (tm_module == NULL) {
            return 0;
        }
        TmSlotSetFuncAppend(tv, tm_module, "/tmp/fuzz.pcap");
        tm_module = TmModuleGetByName("DecodePcapFile");
        if (tm_module == NULL) {
            return 0;
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);
        tmm_modules[TMM_DECODEPCAPFILE].ThreadInit(tv, NULL, (void **) &dtv);
        (void)SC_ATOMIC_SET(tv->tm_slots->slot_next->slot_data, dtv);

        extern intmax_t max_pending_packets;
        max_pending_packets = 128;
        PacketPoolInit();

        initialized = 1;
    }

    //rewrite buffer to a file as libpcap does not have buffer inputs
    if (TestHelperBufferToFile("/tmp/fuzz.pcap", data, size) < 0) {
        return 0;
    }

    if (tmm_modules[TMM_RECEIVEPCAPFILE].ThreadInit(tv, "/tmp/fuzz.pcap", &ptv) == TM_ECODE_OK && ptv != NULL) {
        suricata_ctl_flags = 0;
        tmm_modules[TMM_RECEIVEPCAPFILE].PktAcqLoop(tv, ptv, tv->tm_slots);
        tmm_modules[TMM_RECEIVEPCAPFILE].ThreadDeinit(tv, ptv);
    }

    return 0;
}
