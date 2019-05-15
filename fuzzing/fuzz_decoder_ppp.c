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

#include "decode.h"
#include "decode-ppp.h"
#include "decode-events.h"

ThreadVars tv;
PacketQueue pq;
DecodeThreadVars *dtv;

int LLVMFuzzerInitialize(int *argc, char ***argv) {

  StatsInit();
  ParseSizeInit();
  RunModeRegisterRunModes();
  ConfInit();

  MpmTableSetup();
  SpmTableSetup();
  AppLayerProtoDetectSetup();

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  uint8_t *fuzz_buffer = (uint8_t *)malloc(size);
  memcpy(fuzz_buffer, data, size);

  DefragInit();
  FlowInitConfig(FLOW_QUIET);
  memset(&tv, 0, sizeof(tv));
  dtv = DecodeThreadVarsAlloc(&tv);
  DecodeRegisterPerfCounters(dtv, &tv);
  StatsSetupPrivate(&tv);
  memset(&pq, 0, sizeof(pq));

  Packet *p = PacketGetFromAlloc();
  if (p != NULL) {
      PacketSetData(p, fuzz_buffer, size);
      
      DecodePPP(&tv, dtv, p, fuzz_buffer, size, &pq);
      while (1) {
          Packet *extra_p = PacketDequeue(&pq);
          if (extra_p == NULL)
              break;
          PacketFree(extra_p);
      }
      PacketFree(p);
  }
 
  StatsCounter *head = tv.perf_public_ctx.head;
  while(head->next != NULL){
    StatsCounter *tmp   = head->next;
	  head->next = head->next->next;
	  free(tmp);
  }
  free(head);
  tv.perf_public_ctx.head = NULL;
  free(tv.perf_private_ctx.head);
  tv.perf_private_ctx.head = NULL;

  DecodeThreadVarsFree(&tv, dtv);
  FlowShutdown();
  DefragDestroy();
  memset(&tv, 0, sizeof(tv));
  free(fuzz_buffer);
  return 0;
}
