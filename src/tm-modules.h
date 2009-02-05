#ifndef __TM_MODULES_H__
#define __TM_MODULES_H__

typedef struct _TmModule {
    char *name;
    int (*Init)(ThreadVars *, void *, void **);
    int (*Func)(ThreadVars *, Packet *, void *, PacketQueue *);
    void (*ExitPrintStats)(ThreadVars *, void *);
    int (*Deinit)(ThreadVars *, void *);
    void (*RegisterTests)(void);
} TmModule;

enum {
    TMM_DECODENFQ,
    TMM_VERDICTNFQ,
    TMM_RECEIVENFQ,
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
    TMM_SIZE,
};

TmModule tmm_modules[TMM_SIZE];

TmModule *TmModuleGetByName(char *name);
int TmModuleRegister(char *name, int (*module_func)(ThreadVars *, Packet *, void *));
void TmModuleDebugList(void);
void TmModuleRegisterTests(void);

#endif /* __TM_MODULES_H__ */

