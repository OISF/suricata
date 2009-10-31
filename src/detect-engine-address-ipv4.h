/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#ifndef __DETECT_ENGINE_ADDRESS_IPV4_H__
#define __DETECT_ENGINE_ADDRESS_IPV4_H__

//int DetectAddressCmpIPv4(DetectAddressData *, DetectAddressData *);
//int DetectAddressCutIPv4(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int DetectAddressCutNotIPv4(DetectAddress *, DetectAddress **);
int DetectAddressCmpIPv4(DetectAddress *a, DetectAddress *b);

int DetectAddressCutIPv4(DetectEngineCtx *, DetectAddress *, DetectAddress *, DetectAddress **);
int DetectAddressJoinIPv4(DetectEngineCtx *, DetectAddress *target, DetectAddress *source);
int DetectAddressIsCompleteIPSpaceIPv4(DetectAddress *);

#endif /* __DETECT_ENGINE_ADDRESS_IPV4_H__ */

