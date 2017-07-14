/* Copyright (C) 2007-2017 Open Information Security Foundation
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
#include "util-random.h"

#if defined(HAVE_WINCRYPT_H) && defined(OS_WIN32)
#include <wincrypt.h>

long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    HCRYPTPROV p;
    if (!(CryptAcquireContext(&p, NULL, NULL,
                PROV_RSA_FULL, 0))) {
        return -1;
    }

    long int value = 0;
    if (!CryptGenRandom(p, sizeof(value), (BYTE *)&value)) {
        (void)CryptReleaseContext(p, 0);
        return -1;
    }

    (void)CryptReleaseContext(p, 0);

    return value;
}
#elif defined(HAVE_CLOCK_GETTIME)
long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    srandom(ts.tv_nsec ^ ts.tv_sec);
    long int value = random();
    return value;
}
#else
long int RandomGet(void)
{
    if (g_disable_randomness)
        return 0;

    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    gettimeofday(&tv, NULL);

    srandom(tv.tv_usec ^ tv.tv_sec);
    long int value = random();
    return value;
}
#endif
