/**
 * Copyright (c) 2009 Open Information Security Foundation.
 *
 * \author Victor Julien
 */


#ifndef __DETECT_ADDRESS_H__
#define __DETECT_ADDRESS_H__

/* prototypes */
void DetectAddressRegister (void);
void DetectAddressPrintMemory(void);

DetectAddressHead *DetectAddressHeadInit(void);
void DetectAddressHeadFree(DetectAddressHead *);
void DetectAddressHeadCleanup(DetectAddressHead *);

int DetectAddressParse(DetectAddressHead *, char *);

DetectAddress *DetectAddressInit(void);
void DetectAddressFree(DetectAddress *);

void DetectAddressCleanupList (DetectAddress *);
int DetectAddressAdd(DetectAddress **, DetectAddress *);
void DetectAddressPrintList(DetectAddress *);

int DetectAddressInsert(DetectEngineCtx *, DetectAddressHead *, DetectAddress *);
int DetectAddressJoin(DetectEngineCtx *, DetectAddress *, DetectAddress *);

DetectAddress *DetectAddressLookupInHead(DetectAddressHead *, Address *);
DetectAddress *DetectAddressLookupInList(DetectAddress *, DetectAddress *);

DetectAddress *DetectAddressCopy(DetectAddress *);
void DetectAddressPrint(DetectAddress *);
int DetectAddressCmp(DetectAddress *, DetectAddress *);

#endif /* __DETECT_ADDRESS_H__ */
