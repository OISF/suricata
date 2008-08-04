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

int AddressCutIPv6(DetectAddressData *, DetectAddressData *, DetectAddressData **);
int AddressCmpIPv6(DetectAddressData *, DetectAddressData *);

void DetectAddressIPv6Tests(void);

#endif /* __DETECT_ADDRESS_IPV6_H__ */

