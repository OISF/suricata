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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Functions for getting a random value based on
 * SEI CERT C Coding Standard MSC30-C
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-random.h"


#if !(defined(HAVE_WINCRYPT_H) &&  defined(OS_WIN32))
#if defined(HAVE_CLOCK_GETTIME)

static long int RandomGetClock(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    // coverity[dont_call : FALSE]
    srandom(ts.tv_nsec ^ ts.tv_sec);
    long int value = random();
    return value;
}

#else

static long int RandomGetPosix(void)
{
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);

    // coverity[dont_call : FALSE]
    srandom(tv.tv_usec ^ tv.tv_sec);
    long int value = random();
    return value;
}

#endif
#endif /* !(defined(HAVE_WINCRYPT_H) &&  defined(OS_WIN32)) */

#if defined(HAVE_WINCRYPT_H) && defined(OS_WIN32)
#include <wincrypt.h>

long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    HCRYPTPROV p;
    if (!CryptAcquireContext(&p, NULL, NULL, PROV_RSA_FULL, 0)) {
        DWORD err = GetLastError();
        SCLogDebug("CryptAcquireContext error: %" PRIu32, (uint32_t)err);
        if (err == (DWORD)NTE_BAD_KEYSET) {
            /* The key doesn't exist yet, create it */
            if (!CryptAcquireContext(&p, NULL, NULL, PROV_RSA_FULL,
                                     CRYPT_NEWKEYSET)) {

                SCLogDebug("CryptAcquireContext error: %" PRIu32,
                           (uint32_t)err);
                return -1;
            }
        } else {
            return -1;
        }
    }

    long int value = 0;
    if (!CryptGenRandom(p, sizeof(value), (BYTE *)&value)) {
        (void)CryptReleaseContext(p, 0);
        return -1;
    }

    (void)CryptReleaseContext(p, 0);

    return value;
}
#elif defined(HAVE_GETRANDOM)
long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    long int value = 0;
    int ret = getrandom(&value, sizeof(value), 0);
    /* ret should be sizeof(value), but if it is > 0 and < sizeof(value)
     * it's still better than nothing so we return what we have */
    if (ret <= 0) {
        if (ret == -1 && errno == ENOSYS) {
#if defined(HAVE_CLOCK_GETTIME)
            return RandomGetClock();
#else
            return RandomGetPosix();
#endif
        }
        return -1;
    }
    return value;
}
#elif defined(HAVE_CLOCK_GETTIME)
long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    return RandomGetClock();
}
#else
long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    return RandomGetPosix();
}
#endif
