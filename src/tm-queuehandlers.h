/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __TM_QUEUEHANDLERS_H__
#define __TM_QUEUEHANDLERS_H__

enum {
    TMQH_SIMPLE,
    TMQH_NFQ,
    TMQH_PACKETPOOL,
    TMQH_FLOW,

    TMQH_SIZE,
};

typedef struct Tmqh_ {
    char *name;
    Packet *(*InHandler)(ThreadVars *);
    void (*OutHandler)(ThreadVars *, Packet *);
    void *(*OutHandlerCtxSetup)(char *);
    void (*OutHandlerCtxFree)(void *);
    void (*RegisterTests)(void);
} Tmqh;

Tmqh tmqh_table[TMQH_SIZE];

void TmqhSetup (void);
Tmqh* TmqhGetQueueHandlerByName(char *name);

#endif /* __TM_QUEUEHANDLERS_H__ */
