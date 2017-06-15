/*
 * Copyright (c) 2009,2010 Open Information Security Foundation
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_DCERPC_UDP_H__
#define __APP_LAYER_DCERPC_UDP_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc-common.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

typedef struct DCERPCUDPState_ {
    DCERPCUDP dcerpc;
    uint16_t bytesprocessed;
    uint16_t fraglenleft;
    uint8_t *frag_data;
    DCERPCUuidEntry *uuid_entry;
    TAILQ_HEAD(, DCERPCUuidEntry_) uuid_list;
    DetectEngineState *de_state;
} DCERPCUDPState;

void RegisterDCERPCUDPParsers(void);
void DCERPCUDPParserTests(void);
void DCERPCUDPParserRegisterTests(void);

#endif /* __APP_LAYER_DCERPC_UDP_H__ */
