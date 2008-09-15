/* Address part of the detection engine.
 *
 * Copyright (c) 2008 Victor Julien
 */

#ifndef __DETECT_ADDRESS_IPV6_H__
#define __DETECT_ADDRESS_IPV6_H__

int AddressIPv6Lt(u_int32_t *, u_int32_t *);
int AddressIPv6Gt(u_int32_t *, u_int32_t *);
int AddressIPv6Eq(u_int32_t *, u_int32_t *);
int AddressIPv6Le(u_int32_t *, u_int32_t *);
int AddressIPv6Ge(u_int32_t *, u_int32_t *);

int DetectAddressCutIPv6(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int DetectAddressCutNotIPv6(DetectAddressData *, DetectAddressData **);
int DetectAddressCmpIPv6(DetectAddressData *, DetectAddressData *);

int DetectAddressGroupCutIPv6(DetectAddressGroup *, DetectAddressGroup *, DetectAddressGroup **);

void DetectAddressIPv6Tests(void);

#endif /* __DETECT_ADDRESS_IPV6_H__ */

