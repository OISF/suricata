#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* prototypes */
void DetectAddressRegister (void);
DetectAddressGroupsHead *DetectAddressGroupsHeadInit();
void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *);
void DetectAddressGroupsHeadCleanup(DetectAddressGroupsHead *);
int DetectAddressGroupSetup(DetectAddressGroupsHead *, char *);
int DetectAddressGroupParse(DetectAddressGroupsHead *, char *);
DetectAddressGroup *DetectAddressGroupInit(void);
int DetectAddressGroupAdd(DetectAddressGroup **, DetectAddressGroup *);
void DetectAddressGroupPrintList(DetectAddressGroup *);
void DetectAddressGroupFree(DetectAddressGroup *);
int DetectAddressGroupInsert(DetectEngineCtx *, DetectAddressGroupsHead *, DetectAddressGroup *);
void DetectAddressGroupPrintMemory(void);
void DetectAddressGroupCleanupList (DetectAddressGroup *);
int DetectAddressGroupJoin(DetectEngineCtx *, DetectAddressGroup *target, DetectAddressGroup *source);

DetectAddressGroup *DetectAddressLookupGroup(DetectAddressGroupsHead *, Address *);
DetectAddressGroup *DetectAddressGroupLookup(DetectAddressGroup *, DetectAddressGroup *);

/** \brief address only copy of ag */
DetectAddressGroup *DetectAddressGroupCopy(DetectAddressGroup *);
/** \brief debugging: print a detect address */
void DetectAddressPrint(DetectAddressGroup *);
/** \brief compare the address part of two DetectAddress objects */
int DetectAddressCmp(DetectAddressGroup *, DetectAddressGroup *);
/** \brief parse a address string */
DetectAddressGroup *DetectAddressParse(char *);
#endif /* __DETECT_ADDRESS_H__ */

