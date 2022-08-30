/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Jan Jezek <jjezek@kerio.com>
 *
 * Misc Windows utility functions
 */

#ifdef OS_WIN32

#include "suricata-common.h"
#include "win32-misc.h"
#include "direct.h"
#include "util-ip.h"

void setenv(const char *name, const char *value, int overwrite)
{
    if (overwrite || NULL == getenv(name)) {
        char *str = SCMalloc(strlen(name) + strlen(value) + 2);
        if (unlikely(str == NULL))
            return;
        snprintf(str, strlen(name) + strlen(value) + 1, "%s=%s", name, value);
        putenv(str);
        SCFree(str);
    }
}

void unsetenv(const char *name)
{
    char *str = SCMalloc(strlen(name) + 2);
    if (unlikely(str == NULL))
        return;
    snprintf(str, strlen(name) + 1, "%s=", name);
    putenv(str);
    SCFree(str);
}

/* these functions have been defined on Vista and later */
#if NTDDI_VERSION < NTDDI_VISTA
const char* inet_ntop(int af, const void *src, char *dst, uint32_t cnt)
{
    if (af == AF_INET)
    {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        memcpy(&in.sin_addr, src, sizeof(struct in_addr));
        if (0 == getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST))
            return dst;
    }
    else if (af == AF_INET6)
    {
        struct sockaddr_in6 in6;
        memset(&in6, 0, sizeof(in6));
        in6.sin6_family = AF_INET6;
        memcpy(&in6.sin6_addr, src, sizeof(struct in_addr6));
        if (0 == getnameinfo((struct sockaddr *)&in6, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST))
            return dst;
    }
    return NULL;
}

int inet_pton(int af, const char *src, void *dst)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = af;

    /* as getaddrinfo below seems more liberal that inet_pton on Linux,
     * add this check here that does a guess at the validity of the
     * input address. */
    if (af == AF_INET) {
        if (!IPv4AddressStringIsValid(src))
            return -1;
    } else if (af == AF_INET6) {
        if (!IPv6AddressStringIsValid(src))
            return -1;
    }

    struct addrinfo* result = NULL;
    if (0 != getaddrinfo(src, NULL, &hints, &result))
        return -1;

    if (result) {
        if (result->ai_family == AF_INET) {
            struct sockaddr_in* in = (struct sockaddr_in*)result->ai_addr;
            memcpy(dst, &in->sin_addr, 4);
        }
        else if (result->ai_family == AF_INET6) {
            struct sockaddr_in6* in6 = (struct sockaddr_in6*)result->ai_addr;
            memcpy(dst, &in6->sin6_addr, 16);
        }
        else {
            freeaddrinfo(result);
            return -1;
        }

        freeaddrinfo(result);
        return 1;
    }

    return -1;
}
#endif

#endif /* OS_WIN32 */
