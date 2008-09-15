/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#ifndef __DETECT_ADDRESS_IPV4_H__
#define __DETECT_ADDRESS_IPV4_H__

int DetectAddressCmpIPv4(DetectAddressData *, DetectAddressData *);
int DetectAddressCutIPv4(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int DetectAddressCutNotIPv4(DetectAddressData *, DetectAddressData **);

int DetectAddressGroupCutIPv4(DetectAddressGroup *, DetectAddressGroup *, DetectAddressGroup **);

#endif /* __DETECT_ADDRESS_IPV4_H__ */

