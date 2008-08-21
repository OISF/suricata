#ifndef __DETECT_SIGGROUP_H__
#define __DETECT_SIGGROUP_H__

int SigGroupAppend(DetectAddressGroup *, Signature *);
int SigGroupClean(DetectAddressGroup *ag);
SigGroupHead* SigGroupHeadListGet(SigGroupHead *a);
void SigGroupHeadListClean(void);
void SigGroupHeadAppend(SigGroupHead *);

#endif /* __DETECT_SIGGROUP_H__ */

