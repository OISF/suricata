#ifndef __DETECT_MPM_H__
#define __DETECT_MPM_H__

u_int32_t PacketPatternMatch(ThreadVars *, PatternMatcherThread *, Packet *);
int PacketPatternScan(ThreadVars *t, Packet *p, u_int8_t mpm_instance);
void PacketPatternCleanup(ThreadVars *, PatternMatcherThread *, u_int8_t);
void PatternMatchPrepare(Signature *);
void PatternMatcherThreadInfo(ThreadVars *, PatternMatcherThread *);
void PatternMatchDestroy(void);

int PatternMatcherThreadInit(ThreadVars *, void **);
int PatternMatcherThreadDeinit(ThreadVars *, void *);

#endif /* __DETECT_MPM_H__ */

