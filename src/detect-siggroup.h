#ifndef __DETECT_SIGGROUP_H__
#define __DETECT_SIGGROUP_H__

int SigGroupAppend(DetectAddressGroup *, Signature *);
int SigGroupClean(DetectAddressGroup *ag);
SigGroupHead* SigGroupHeadListGet(SigGroupHead *a);
SigGroupHead* SigGroupHeadListGetMpm(SigGroupHead *a);
SigGroupHead* SigGroupHeadListGetMpmUri(SigGroupHead *a);
void SigGroupHeadListClean(void);
void SigGroupHeadAppend(SigGroupHead *);
void SigGroupHeadFree(SigGroupHead *);
int SigGroupListCopyPrepend(DetectAddressGroup *src, DetectAddressGroup *dst);
int SigGroupListCopyAppend(DetectAddressGroup *src, DetectAddressGroup *dst);
void SigGroupHeadListClean(void);
int SigGroupListClean(SigGroupHead *sh);
void DetectSigGroupPrintMemory(void);

int SigGroupContentLoad(SigGroupHead *sgh);
int SigGroupUricontentLoad(SigGroupHead *sgh);

int SigGroupListContentClean(SigGroupHead *sh);
int SigGroupListUricontentClean(SigGroupHead *sh);

int SigGroupContentCmp(SigGroupContent *, SigGroupContent *);
int SigGroupUricontentCmp(SigGroupUricontent *, SigGroupUricontent *);

void SigGroupHeadFreeMpmArrays(void);

#endif /* __DETECT_SIGGROUP_H__ */

