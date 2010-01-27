/**
 * Copyright (c) 2009 Open Information Security Foundation.
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_ADDRESS_IPV6_H__
#define __DETECT_ENGINE_ADDRESS_IPV6_H__

int AddressIPv6Lt(uint32_t *, uint32_t *);
int AddressIPv6Gt(uint32_t *, uint32_t *);
int AddressIPv6Eq(uint32_t *, uint32_t *);
int AddressIPv6Le(uint32_t *, uint32_t *);
int AddressIPv6Ge(uint32_t *, uint32_t *);

int DetectAddressCutNotIPv6(DetectAddress *, DetectAddress **);
int DetectAddressCmpIPv6(DetectAddress *a, DetectAddress *b);

int DetectAddressCutIPv6(DetectEngineCtx *, DetectAddress *, DetectAddress *,
                         DetectAddress **);
int DetectAddressJoinIPv6(DetectEngineCtx *, DetectAddress *, DetectAddress *);

void DetectAddressIPv6Tests(void);

#endif /* __DETECT_ENGINE_ADDRESS_IPV6_H__ */

