#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* prototypes */
void DetectAddressRegister (void);
void DetectAddressGroupPrintMemory(void);

DetectAddressGroupsHead *DetectAddressGroupsHeadInit(void);
void DetectAddressGroupsHeadFree(DetectAddressGroupsHead *);
void DetectAddressGroupsHeadCleanup(DetectAddressGroupsHead *);

int DetectAddressGroupParse(DetectAddressGroupsHead *, char *);

DetectAddressGroup *DetectAddressGroupInit(void);
void DetectAddressGroupFree(DetectAddressGroup *);

void DetectAddressGroupCleanupList (DetectAddressGroup *);
int DetectAddressGroupAdd(DetectAddressGroup **, DetectAddressGroup *);
void DetectAddressGroupPrintList(DetectAddressGroup *);

int DetectAddressGroupInsert(DetectEngineCtx *, DetectAddressGroupsHead *, DetectAddressGroup *);
int DetectAddressGroupJoin(DetectEngineCtx *, DetectAddressGroup *, DetectAddressGroup *);

DetectAddressGroup *DetectAddressLookupInHead(DetectAddressGroupsHead *, Address *);
DetectAddressGroup *DetectAddressLookupInList(DetectAddressGroup *, DetectAddressGroup *);

/** \brief address only copy of ag */
DetectAddressGroup *DetectAddressGroupCopy(DetectAddressGroup *);
/** \brief debugging: print a detect address */
void DetectAddressPrint(DetectAddressGroup *);
/** \brief compare the address part of two DetectAddress objects */
int DetectAddressCmp(DetectAddressGroup *, DetectAddressGroup *);

#endif /* __DETECT_ADDRESS_H__ */

