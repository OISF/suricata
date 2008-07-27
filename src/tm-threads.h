#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

void Tm1SlotSetFunc(ThreadVars *, TmModule *);
void Tm2SlotSetFunc1(ThreadVars *, TmModule *);
void Tm2SlotSetFunc2(ThreadVars *, TmModule *);
ThreadVars *TmThreadCreate(char *name, char *inq_name, char *inqh_name, char *outq_name, char *outqh_name, char *slots);
int TmThreadSpawn(ThreadVars *);
void TmThreadKillThreads(void);
void TmThreadAppend(ThreadVars *);

#endif /* __TM_THREADS_H__ */

