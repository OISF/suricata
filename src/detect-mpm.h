#ifndef __DETECT_MPM_H__
#define __DETECT_MPM_H__

MpmCtx mpm_ctx[MPM_INSTANCE_MAX];

u_int32_t PacketPatternMatch(ThreadVars *, PatternMatcherThread *, Packet *);
int PacketPatternScan(ThreadVars *t, Packet *p, u_int8_t mpm_instance);
void PacketPatternCleanup(ThreadVars *, PatternMatcherThread *);
void PatternMatchPrepare(MpmCtx *);
int PatternMatchPrepareGroup(SigGroupHead *);
void PatternMatcherThreadInfo(ThreadVars *, PatternMatcherThread *);
void PatternMatchDestroy(MpmCtx *);
void PatternMatchDestroyGroup(SigGroupHead *);

int PatternMatcherThreadInit(ThreadVars *, void **);
int PatternMatcherThreadDeinit(ThreadVars *, void *);

#endif /* __DETECT_MPM_H__ */

