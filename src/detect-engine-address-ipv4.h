/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#ifndef __DETECT_ENGINE_ADDRESS_IPV4_H__
#define __DETECT_ENGINE_ADDRESS_IPV4_H__

int DetectAddressCmpIPv4(DetectAddressData *, DetectAddressData *);
int DetectAddressCutIPv4(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int DetectAddressCutNotIPv4(DetectAddressData *, DetectAddressData **);

int DetectAddressGroupCutIPv4(DetectEngineCtx *, DetectAddressGroup *, DetectAddressGroup *, DetectAddressGroup **);
int DetectAddressGroupJoinIPv4(DetectEngineCtx *, DetectAddressGroup *target, DetectAddressGroup *source);
int DetectAddressGroupIsCompleteIPSpaceIPv4(DetectAddressGroup *);

#endif /* __DETECT_ENGINE_ADDRESS_IPV4_H__ */

