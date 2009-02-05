#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* prototypes */
void DetectAddressRegister (void);
DetectAddressGroupsHead *DetectAddressGroupsHeadInit();
void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *);
void DetectAddressGroupsHeadCleanup(DetectAddressGroupsHead *);
DetectAddressData *DetectAddressDataInit(void);
void DetectAddressDataFree(DetectAddressData *);
void DetectAddressDataPrint(DetectAddressData *);
DetectAddressData *DetectAddressDataCopy(DetectAddressData *);
int DetectAddressGroupSetup(DetectAddressGroupsHead *, char *);
int DetectAddressCmp(DetectAddressData *, DetectAddressData *);
DetectAddressData *DetectAddressParse(char *);
DetectAddressGroup *DetectAddressLookupGroup(DetectAddressGroupsHead *, Address *);
int DetectAddressGroupParse(DetectAddressGroupsHead *, char *);
DetectAddressGroup *DetectAddressGroupInit(void);
int DetectAddressGroupAdd(DetectAddressGroup **, DetectAddressGroup *);
DetectAddressGroup *DetectAddressGroupLookup(DetectAddressGroup *, DetectAddressData *);
void DetectAddressGroupPrintList(DetectAddressGroup *);
void DetectAddressGroupFree(DetectAddressGroup *);
int DetectAddressGroupInsert(DetectEngineCtx *, DetectAddressGroupsHead *, DetectAddressGroup *);
void DetectAddressGroupPrintMemory(void);
void DetectAddressGroupCleanupList (DetectAddressGroup *);
int DetectAddressGroupJoin(DetectEngineCtx *, DetectAddressGroup *target, DetectAddressGroup *source);

#endif /* __DETECT_ADDRESS_H__ */

