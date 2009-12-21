/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"
#include "tmqh-simple.h"
#include "tmqh-nfq.h"
#include "tmqh-packetpool.h"
#include "tmqh-flow.h"

void TmqhSetup (void) {
    memset(&tmqh_table, 0, sizeof(tmqh_table));

    TmqhSimpleRegister();
    TmqhNfqRegister();
    TmqhPacketpoolRegister();
    TmqhFlowRegister();
}

Tmqh* TmqhGetQueueHandlerByName(char *name) {
    int i;

    for (i = 0; i < TMQH_SIZE; i++) {
        if (strcmp(name, tmqh_table[i].name) == 0)
            return &tmqh_table[i];
    }

    return NULL;
}

