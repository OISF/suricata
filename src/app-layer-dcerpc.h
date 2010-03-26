/* Copyright (c) 2009,2010 Open Information Security Foundation */

/**
 * \file
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_DCERPC_H__
#define __APP_LAYER_DCERPC_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc-common.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

typedef struct DCERPCState_ {
     DCERPC dcerpc;
} DCERPCState;

void RegisterDCERPCParsers(void);
void DCERPCParserTests(void);
void DCERPCParserRegisterTests(void);

#endif /* __APP_LAYER_DCERPC_H__ */

