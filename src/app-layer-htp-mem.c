/* Copyright (C) 2022 Open Information Security Foundation
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
 * \ingroup httplayer
 *
 * @{
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * This file provides a memory handling for the HTTP protocol support.
 */

#include "suricata-common.h"
#include "suricata.h"

#include "conf.h"
#include "util-mem.h"
#include "util-misc.h"

#include "app-layer-htp-mem.h"

SC_ATOMIC_DECLARE(uint64_t, htp_config_memcap);
SC_ATOMIC_DECLARE(uint64_t, htp_memuse);
SC_ATOMIC_DECLARE(uint64_t, htp_memcap);

void HTPParseMemcap()
{
    const char *conf_val;

    SC_ATOMIC_INIT(htp_config_memcap);

    /** set config values for memcap, prealloc and hash_size */
    uint64_t memcap;
    if ((ConfGet("app-layer.protocols.http.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing http.memcap "
                       "from conf file - %s.  Killing engine",
                       conf_val);
            exit(EXIT_FAILURE);
        } else {
            SC_ATOMIC_SET(htp_config_memcap, memcap);
        }
        SCLogInfo("HTTP memcap: %"PRIu64, SC_ATOMIC_GET(htp_config_memcap));
    } else {
        /* default to unlimited */
        SC_ATOMIC_SET(htp_config_memcap, 0);
    }

    SC_ATOMIC_INIT(htp_memuse);
    SC_ATOMIC_INIT(htp_memcap);
}

static void HTPIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(htp_memuse, size);
    return;
}

static void HTPDecrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_SUB(htp_memuse, size);
    return;
}

uint64_t HTPMemuseGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(htp_memuse);
    return tmpval;
}

uint64_t HTPMemcapGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(htp_memcap);
    return tmpval;
}

/**
 *  \brief Check if alloc'ing "size" would mean we're over memcap
 *
 *  \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
static int HTPCheckMemcap(uint64_t size)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(htp_config_memcap);
    if (memcapcopy == 0 || size + SC_ATOMIC_GET(htp_memuse) <= memcapcopy)
        return 1;
    (void) SC_ATOMIC_ADD(htp_memcap, 1);
    return 0;
}

/**
 *  \brief Update memcap value
 *
 *  \param size new memcap value
 */
int HTPSetMemcap(uint64_t size)
{
    if (size == 0 || (uint64_t)SC_ATOMIC_GET(htp_memuse) < size) {
        SC_ATOMIC_SET(htp_config_memcap, size);
        return 1;
    }
    return 0;
}

/**
 *  \brief Update memcap value
 *
 *  \retval memcap value
 */
uint64_t HTPGetMemcap(void)
{
    uint64_t memcapcopy = SC_ATOMIC_GET(htp_config_memcap);
    return memcapcopy;
}

void *HTPMalloc(size_t size)
{
    void *ptr = NULL;

    if (HTPCheckMemcap((uint32_t)size) == 0)
        return NULL;

    ptr = SCMalloc(size);

    if (unlikely(ptr == NULL))
        return NULL;

    HTPIncrMemuse((uint64_t)size);

    return ptr;
}

void *HTPCalloc(size_t n, size_t size)
{
    void *ptr = NULL;

    if (HTPCheckMemcap((uint32_t)(n * size)) == 0)
        return NULL;

    ptr = SCCalloc(n, size);

    if (unlikely(ptr == NULL))
        return NULL;

    HTPIncrMemuse((uint64_t)(n * size));

    return ptr;
}

void *HTPRealloc(void *ptr, size_t orig_size, size_t size)
{
    if (size > orig_size) {
        if (HTPCheckMemcap((uint32_t)(size - orig_size)) == 0)
            return NULL;
    }

    void *rptr = SCRealloc(ptr, size);
    if (rptr == NULL)
        return NULL;

    if (size > orig_size) {
        HTPIncrMemuse((uint64_t)(size - orig_size));
    } else {
        HTPDecrMemuse((uint64_t)(orig_size - size));
    }

    return rptr;
}

void HTPFree(void *ptr, size_t size)
{
    SCFree(ptr);

    HTPDecrMemuse((uint64_t)size);
}

/**
 * @}
 */
