/*
 * Copyright (c) 2009,2010 Open Information Security Foundation
 * app-layer-dcerpc.h
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef APPLAYERDCERPC_H_
#define APPLAYERDCERPC_H_
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc-common.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

typedef struct DCERPCState_ {
     DCERPC dcerpc;
}DCERPCState;

void RegisterDCERPCParsers(void);
void DCERPCParserTests(void);
void DCERPCParserRegisterTests(void);

#endif /* APPLAYERDCERPC_H_ */

