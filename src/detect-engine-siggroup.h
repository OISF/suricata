#ifndef __DETECT_SIGGROUP_H__
#define __DETECT_SIGGROUP_H__

/* XXX cleanup */

int SigGroupHeadAppendSig(DetectEngineCtx *, SigGroupHead **, Signature *);
int SigGroupHeadClearSigs(SigGroupHead *);
int SigGroupHeadCopySigs(DetectEngineCtx *, SigGroupHead *, SigGroupHead **);

int SigGroupHeadLoadContent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadLoadUricontent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadClearContent(SigGroupHead *);
int SigGroupHeadClearUricontent(SigGroupHead *);

void SigGroupHeadFree(SigGroupHead *);

void SigGroupHeadFreeMpmArrays(DetectEngineCtx *);

SigGroupHead *SigGroupHeadHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadMpmHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadMpmUriHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadDPortHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadSPortHashLookup(DetectEngineCtx *, SigGroupHead *);

int SigGroupHeadMpmHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadMpmUriHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadDPortHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadSPortHashAdd(DetectEngineCtx *, SigGroupHead *);

void SigGroupHeadHashFree(DetectEngineCtx *);
void SigGroupHeadMpmHashFree(DetectEngineCtx *);
void SigGroupHeadMpmUriHashFree(DetectEngineCtx *);
void SigGroupHeadDPortHashFree(DetectEngineCtx *);
void SigGroupHeadSPortHashFree(DetectEngineCtx *);

int SigGroupHeadHashInit(DetectEngineCtx *);
int SigGroupHeadMpmHashInit(DetectEngineCtx *);
int SigGroupHeadMpmUriHashInit(DetectEngineCtx *);
int SigGroupHeadDPortHashInit(DetectEngineCtx *);
int SigGroupHeadSPortHashInit(DetectEngineCtx *);

void SigGroupHeadSetSigCnt(SigGroupHead *sgh, uint32_t max_idx);
int SigGroupHeadBuildMatchArray (DetectEngineCtx *de_ctx, SigGroupHead *sgh, uint32_t max_idx);
void SigGroupHeadFreeSigArrays(DetectEngineCtx *de_ctx);

#endif /* __DETECT_SIGGROUP_H__ */

