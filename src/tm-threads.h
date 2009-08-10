#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_MAX,
};

extern ThreadVars *tv_root[TVT_MAX];

extern pthread_mutex_t tv_root_lock;

void Tm1SlotSetFunc(ThreadVars *, TmModule *, void *);

void Tm2SlotSetFunc1(ThreadVars *, TmModule *, void *);

void Tm2SlotSetFunc2(ThreadVars *, TmModule *, void *);

void Tm3SlotSetFunc1(ThreadVars *, TmModule *, void *);

void Tm3SlotSetFunc2(ThreadVars *, TmModule *, void *);

void Tm3SlotSetFunc3(ThreadVars *, TmModule *, void *);

void TmVarSlotSetFuncAppend(ThreadVars *, TmModule *, void *);


ThreadVars *TmThreadCreate(char *name, char *inq_name, char *inqh_name,
                           char *outq_name, char *outqh_name, char *slots,
                           void *(fn_p)(void *), int);

int TmThreadSpawn(ThreadVars *, int, int);

void TmThreadKillThreads(void);

void TmThreadAppend(ThreadVars *, int);

int TmThreadSetCPUAffinity(ThreadVars *, int);

void TmThreadInitMC(ThreadVars *);

void TmThreadTestThreadUnPaused(ThreadVars *);

void TmThreadContinue(ThreadVars *);

void TmThreadContinueThreads(void);

void TmThreadPause(ThreadVars *);

void TmThreadPauseThreads(void);

#endif /* __TM_THREADS_H__ */

