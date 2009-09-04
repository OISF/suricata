#ifndef __TM_MODULES_H__
#define __TM_MODULES_H__

#include "threadvars.h"

typedef struct TmModule_ {
    char *name;

    /** thread handling */
    int (*ThreadInit)(ThreadVars *, void *, void **);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
    int (*ThreadDeinit)(ThreadVars *, void *);

    /** the packet processing function */
    int (*Func)(ThreadVars *, Packet *, void *, PacketQueue *);

    void (*RegisterTests)(void);
} TmModule;

enum {
    TMM_DECODENFQ,
    TMM_VERDICTNFQ,
    TMM_RECEIVENFQ,
    TMM_RECEIVEPCAP,
    TMM_RECEIVEPCAPFILE,
    TMM_DECODEPCAP,
    TMM_DECODEPCAPFILE,
    TMM_DETECT,
    TMM_ALERTFASTLOG,
    TMM_ALERTFASTLOG4,
    TMM_ALERTFASTLOG6,
    TMM_ALERTUNIFIEDLOG,
    TMM_ALERTUNIFIEDALERT,
    TMM_ALERTDEBUGLOG,
    TMM_RESPONDREJECT,
    TMM_LOGHTTPLOG,
    TMM_LOGHTTPLOG4,
    TMM_LOGHTTPLOG6,
    TMM_STREAMTCP,
    TMM_SIZE,
};

TmModule tmm_modules[TMM_SIZE];

TmModule *TmModuleGetByName(char *name);
int TmModuleRegister(char *name, int (*module_func)(ThreadVars *, Packet *, void *));
void TmModuleDebugList(void);
void TmModuleRegisterTests(void);

#endif /* __TM_MODULES_H__ */

