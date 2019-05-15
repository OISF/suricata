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
#include "util-decode-mime.h"

#include "decode.h"
#include "decode-ppp.h"
#include "decode-events.h"
static int MimeParserDataFromFileCB (const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state) {
    return MIME_DEC_OK;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t line_count = 0;
  MimeDecParseState *state = MimeDecInitParser((void*)data,MimeParserDataFromFileCB);
  
  (void) MimeDecParseLine(data, size, size, state);

  /* Completed */
  (void)MimeDecParseComplete(state);
  if (state->msg) {
      MimeDecFreeEntity(state->msg);
  }

  /* De Init parser */
  MimeDecDeInitParser(state);

  return 0;
}
