#ifndef __DETECT_SIGGROUP_H__
#define __DETECT_SIGGROUP_H__

/* XXX cleanup */

int SigGroupHeadAppendSig(SigGroupHead **, Signature *);
int SigGroupHeadClearSigs(SigGroupHead *);
int SigGroupHeadCopySigs(SigGroupHead *, SigGroupHead **);

int SigGroupHeadLoadContent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadLoadUricontent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadClearContent(SigGroupHead *);
int SigGroupHeadClearUricontent(SigGroupHead *);

void SigGroupHeadFree(SigGroupHead *);

void SigGroupHeadFreeMpmArrays(void);

SigGroupHead *SigGroupHeadHashLookup(SigGroupHead *sgh);
SigGroupHead *SigGroupHeadPortHashLookup(SigGroupHead *sgh);
SigGroupHead *SigGroupHeadSPortHashLookup(SigGroupHead *sgh);
SigGroupHead *SigGroupHeadMpmHashLookup(SigGroupHead *sgh);
SigGroupHead *SigGroupHeadMpmUriHashLookup(SigGroupHead *sgh);

int SigGroupHeadPortHashAdd(SigGroupHead *sgh);
int SigGroupHeadSPortHashAdd(SigGroupHead *sgh);
int SigGroupHeadMpmHashAdd(SigGroupHead *sgh);
int SigGroupHeadMpmUriHashAdd(SigGroupHead *sgh);
int SigGroupHeadHashAdd(SigGroupHead *sgh);

void SigGroupHeadHashFree(void);
void SigGroupHeadPortHashFree(void);
void SigGroupHeadSPortHashFree(void);
void SigGroupHeadMpmHashFree(void);
void SigGroupHeadMpmUriHashFree(void);

int SigGroupHeadMpmHashInit(void);
int SigGroupHeadMpmUriHashInit(void);
int SigGroupHeadPortHashInit(void);
int SigGroupHeadSPortHashInit(void);
int SigGroupHeadHashInit(void);

void SigGroupHeadSetSigCnt(SigGroupHead *sgh, u_int32_t max_idx);
int SigGroupHeadBuildMatchArray (DetectEngineCtx *de_ctx, SigGroupHead *sgh, u_int32_t max_idx);
void SigGroupHeadFreeSigArrays(void);

#endif /* __DETECT_SIGGROUP_H__ */

