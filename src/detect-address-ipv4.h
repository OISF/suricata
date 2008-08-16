/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#ifndef __DETECT_ADDRESS_IPV4_H__
#define __DETECT_ADDRESS_IPV4_H__

int AddressCmpIPv4(DetectAddressData *, DetectAddressData *);
int AddressCutIPv4(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int AddressCutNotIPv4(DetectAddressData *, DetectAddressData **);

#endif /* __DETECT_ADDRESS_IPV4_H__ */

