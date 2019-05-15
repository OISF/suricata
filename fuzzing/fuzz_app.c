// Copyright (c) 2018 Code Intelligence. All rights reserved.

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "suricata-common.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "flow-util.h"
#include "flow.h"
#include "util-mpm.h"
#include "util-spm.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  MpmTableSetup();
  SpmTableSetup();
  AppLayerProtoDetectSetup();
  AppLayerParserSetup();
  AppLayerParserRegisterProtocolParsers();

  return 0;
}

AppProto AppProtoFromData(const uint8_t data) {
  if (data > ALPROTO_MAX) return ALPROTO_FAILED;
  return data;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return 0;

  // Data setup
  AppProto alproto = AppProtoFromData(*data);
  if (alproto == ALPROTO_FAILED) return 0;
  if (alproto == ALPROTO_HTTP) return 0;
  if (alproto == ALPROTO_FTPDATA) return 0;

  size_t input_len = size - 1;
  uint8_t *input = malloc(input_len);
  memcpy(input, data + 1, input_len);

  Flow *f = NULL;
  TcpSession ssn;
  AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

  memset(&ssn, 0, sizeof(ssn));

  f = calloc(1, sizeof(Flow));
  if (f == NULL) goto out;
  FLOW_INITIALIZE(f);

  f->flags |= FLOW_IPV4;
  f->src.addr_data32[0] = 0x01020304;
  f->dst.addr_data32[0] = 0x05060708;
  f->sp = 10000;
  f->dp = 80;
  f->protoctx = &ssn;
  f->proto = IPPROTO_TCP;
  f->protomap = FlowGetProtoMapping(f->proto);
  f->alproto = alproto;

  int start = 1;
  int flip = 0;

  uint8_t flags = STREAM_TOSERVER | STREAM_START;

  AppLayerParserParse(NULL, alp_tctx, f, alproto, flags, input, input_len);

out:
  if (alp_tctx) AppLayerParserThreadCtxFree(alp_tctx);
  if (f) FlowFree(f);
  if (input) free(input);

  return 0;
}
