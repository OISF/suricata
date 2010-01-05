/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_ADDRESS_IPV4_H__
#define __DETECT_ENGINE_ADDRESS_IPV4_H__

int DetectAddressCutNotIPv4(DetectAddress *, DetectAddress **);
int DetectAddressCmpIPv4(DetectAddress *a, DetectAddress *b);

int DetectAddressCutIPv4(DetectEngineCtx *, DetectAddress *,
                         DetectAddress *, DetectAddress **);
int DetectAddressJoinIPv4(DetectEngineCtx *, DetectAddress *target,
                          DetectAddress *source);
int DetectAddressIsCompleteIPSpaceIPv4(DetectAddress *);

void DetectAddressIPv4Tests(void);

#endif /* __DETECT_ENGINE_ADDRESS_IPV4_H__ */

