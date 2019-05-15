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

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-ssl.h"
#include "app-layer-dns-tcp.h"
#include "app-layer-dns-udp.h"
#include "app-layer-ssh.h"
#include "app-layer-ftp.h"
#include "app-layer-smtp.h"
#include "app-layer-smb.h"
#include "app-layer-modbus.h"
#include "app-layer-enip.h"
#include "app-layer-dnp3.h"


int LLVMFuzzerInitialize(int *argc, char ***argv) {
  time_t t; 
  MpmTableSetup();
  SpmTableSetup();
  AppLayerProtoDetectSetup();
  AppLayerParserSetup();
  AppLayerParserRegisterProtocolParsers();
  /* Intializes random number generator */
   srand((unsigned) time(&t));
  return 0;
}

AppProto AppProtoFromData() {
  return rand() % ALPROTO_MAX;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 63) return 0;

  // Data setup
  AppProto alproto = AppProtoFromData();
  if (alproto == ALPROTO_FTPDATA) return 0;

  size_t input_len = size;
  uint8_t *input = malloc(input_len+1);
  memcpy(input, data, input_len);

  Flow *f = NULL;
  TcpSession ssn;
  AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

  memset(&ssn, 0, sizeof(ssn));

  f = calloc(1, sizeof(Flow));
  if (f == NULL) goto out;
  FLOW_INITIALIZE(f);

  f->flags |= FLOW_IPV6;
  f->src.addr_data32[0] = 0x01020304;
  f->dst.addr_data32[0] = 0x05060708;
  f->sp = rand() % 65535;
  f->dp = rand() % 65535;
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
