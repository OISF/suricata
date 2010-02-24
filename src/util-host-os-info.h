/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_HOST_OS_INFO_H__
#define __UTIL_HOST_OS_INFO_H__

#define SC_HINFO_IS_IPV6 0
#define SC_HINFO_IS_IPV4 1

int SCHInfoAddHostOSInfo(char *, char *, int);
int SCHInfoGetHostOSFlavour(char *);
int SCHInfoGetIPv4HostOSFlavour(uint8_t *);
int SCHInfoGetIPv6HostOSFlavour(uint8_t *);
void SCHInfoCleanResources(void);
void SCHInfoLoadFromConfig(void);
void SCHInfoRegisterTests(void);

#endif /* __UTIL_HOST_OS_INFO_H__ */
