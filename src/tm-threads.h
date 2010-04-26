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
void TmThreadKillThread(ThreadVars *);
void TmThreadKillThreads(void);
void TmThreadAppend(ThreadVars *, int);
void TmThreadRemove(ThreadVars *, int);

TmEcode TmThreadSetCPUAffinity(ThreadVars *, uint16_t);
TmEcode TmThreadSetThreadPriority(ThreadVars *, int);
TmEcode TmThreadSetupOptions(ThreadVars *);
void TmThreadSetPrio(ThreadVars *);

void TmThreadInitMC(ThreadVars *);
void TmThreadTestThreadUnPaused(ThreadVars *);
void TmThreadContinue(ThreadVars *);
void TmThreadContinueThreads(void);
void TmThreadPause(ThreadVars *);
void TmThreadPauseThreads(void);
void TmThreadCheckThreadState(void);
TmEcode TmThreadWaitOnThreadInit(void);
ThreadVars *TmThreadsGetCallingThread(void);

/**
 *  \brief Check if a thread flag is set
 *
 *  \retval 1 flag is set
 *  \retval 0 flag is not set
 */
static inline int TmThreadsCheckFlag(ThreadVars *tv, uint8_t flag) { \
    int r;
    if (SCSpinLock(&tv->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return 0;
    }

    r = (tv->flags & flag);
    SCSpinUnlock(&tv->flags_spinlock);
    return r;
}

/**
 *  \brief Set a thread flag
 */
static inline void TmThreadsSetFlag(ThreadVars *tv, uint8_t flag) {
    if (SCSpinLock(&tv->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return;
    }

    tv->flags |= flag;
    SCSpinUnlock(&tv->flags_spinlock);
}

/**
 *  \brief Unset a thread flag
 */
static inline void TmThreadsUnsetFlag(ThreadVars *tv, uint8_t flag) {
    if (SCSpinLock(&tv->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return;
    }

    tv->flags &= ~flag;
    SCSpinUnlock(&tv->flags_spinlock);
}

#endif /* __TM_THREADS_H__ */

