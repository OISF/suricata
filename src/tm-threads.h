#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

#include "tm-modules.h"

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_MAX,
};

extern ThreadVars *tv_root[TVT_MAX];

extern SCMutex tv_root_lock;

void Tm1SlotSetFunc(ThreadVars *, TmModule *, void *);

void TmVarSlotSetFuncAppend(ThreadVars *, TmModule *, void *);

ThreadVars *TmThreadCreate(char *, char *, char *, char *, char *, char *,
                           void *(fn_p)(void *), int);

ThreadVars *TmThreadCreatePacketHandler(char *, char *, char *, char *, char *,
                                        char *);

ThreadVars *TmThreadCreateMgmtThread(char *name, void *(fn_p)(void *), int);

TmEcode TmThreadSpawn(ThreadVars *);

void TmThreadSetFlags(ThreadVars *, uint8_t);

void TmThreadSetAOF(ThreadVars *, uint8_t);

void TmThreadKillThreads(void);

void TmThreadAppend(ThreadVars *, int);

TmEcode TmThreadSetCPUAffinity(ThreadVars *, int);

void TmThreadInitMC(ThreadVars *);

void TmThreadTestThreadUnPaused(ThreadVars *);

void TmThreadContinue(ThreadVars *);

void TmThreadContinueThreads(void);

void TmThreadPause(ThreadVars *);

void TmThreadPauseThreads(void);

void TmThreadCheckThreadState(void);

TmEcode TmThreadWaitOnThreadInit(void);

inline int TmThreadsCheckFlag(ThreadVars *, uint8_t);
inline void TmThreadsSetFlag(ThreadVars *, uint8_t);

ThreadVars *TmThreadsGetCallingThread(void);

#endif /* __TM_THREADS_H__ */

