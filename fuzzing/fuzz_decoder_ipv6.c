// Copyright (c) 2018 Code Intelligence. All rights reserved.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "decode.h"
#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-detect-proto.h"
#include "app-layer.h"
#include "tm-threads.h"
#include "util-error.h"
#include "util-print.h"
#include "tmqh-packetpool.h"
#include "util-profiling.h"
#include "pkt-var.h"
#include "util-mpm-ac.h"
#include "output.h"
#include "output-flow.h"
#include "defrag.h"
#include "flow.h"
#include "util-misc.h"


SCInstance suricata;
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

static void FuzzySCInstanceInit(SCInstance *suri, const char *progname)
{
  memset(suri, 0x00, sizeof(*suri));

  suri->progname = progname;
  suri->run_mode = RUNMODE_UNKNOWN;

  memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
  suri->sig_file = NULL;
  suri->sig_file_exclusive = FALSE;
  suri->pid_filename = NULL;
  suri->regex_arg = NULL;

  suri->keyword_info = NULL;
  suri->runmode_custom_mode = NULL;
#ifndef OS_WIN32
  suri->user_name = NULL;
  suri->group_name = NULL;
  suri->do_setuid = FALSE;
  suri->do_setgid = FALSE;
  suri->userid = 0;
  suri->groupid = 0;
#endif /* OS_WIN32 */
  suri->delayed_detect = 0;
  suri->daemon = 0;
  suri->offline = 0;
  suri->verbose = 0;
  /* use -1 as unknown */
  suri->checksum_validation = -1;
  suri->disabled_detect = 0;
}

ThreadVars tv;
PacketQueue pq;
DecodeThreadVars *dtv;

int LLVMFuzzerInitialize(int *argc, char ***argv) {

  FuzzySCInstanceInit(&suricata, "fuzz-suricata");
  SC_ATOMIC_INIT(engine_stage);
  // SCLogInitLogModule(NULL);
  (void)SCSetThreadName("Suricata-Main");
  ParseSizeInit();
  RunModeRegisterRunModes();
  ConfInit();

  MpmTableSetup();
  SpmTableSetup();
  AppLayerProtoDetectSetup();

  DefragInit();
  FlowInitConfig(FLOW_QUIET);
  memset(&tv, 0, sizeof(tv));
  dtv = DecodeThreadVarsAlloc(&tv);
  DecodeRegisterPerfCounters(dtv, &tv);
  StatsSetupPrivate(&tv);
  memset(&pq, 0, sizeof(pq));

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  uint8_t *data_cpy = malloc(size);
  memcpy(data_cpy, data, size);

  Packet *p = PacketGetFromAlloc();
  if (p != NULL) {
    PacketSetData(p, data_cpy, size);
    DecodeIPV6(&tv, dtv, p, data_cpy, size, &pq);
    for (;;) {
      Packet *extra_p = PacketDequeue(&pq);
      if (extra_p == NULL)
        break;
      PacketFree(extra_p);
    }
    PacketFree(p);
  }

  //DecodeThreadVarsFree(&tv, dtv);
  //FlowShutdown();
  //DefragDestroy();
  free(data_cpy);


  return 0;
}
