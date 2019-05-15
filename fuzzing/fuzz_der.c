// Copyright (c) 2018 Code Intelligence. All rights reserved.

#include <stdint.h>
#include <stdlib.h>
#include "util-decode-der.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint32_t errcode;
  Asn1Generic *asn1 = DecodeDer(data, size, &errcode);
  DerFree(asn1);

  return 0;
}