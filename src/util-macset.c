/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 *
 * Set-like data store for MAC addresses. Implemented as array for memory
 * locality reasons as the expected number of items is typically low.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-macset.h"

typedef uint8_t MacAddr[6];

struct MacSet_ {
    MacAddr *buf[2];
    unsigned long size,
                  last[2];
};

MacSet* MacSetInit(int size)
{
    MacSet *ms = SCCalloc(1, sizeof(*ms));
    if (unlikely(ms == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate MacSet memory.");
    }
    ms->buf[TOSERVER] = SCCalloc(size, sizeof(MacAddr));
    if (unlikely(ms->buf[TOSERVER] == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate MacSet memory.");
    }
    ms->buf[TOCLIENT] = SCCalloc(size, sizeof(MacAddr));
    if (unlikely(ms->buf[TOCLIENT] == NULL)) {
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate MacSet memory.");
    }
    ms->size = size;
    ms->last[TOSERVER] = ms->last[TOCLIENT] = 0;
    return ms;
}

int MacSetAdd(MacSet *ms, uint8_t *addr, int direction)
{
    unsigned long i = 0;
    if (ms == NULL)
        return 0;
    if (unlikely(ms->last[direction] == ms->size)) {
        /* MacSet full */
        return 0;
    }
    if (ms->last[direction] > 0) {
        for (i = ms->last[direction]-1; i < ms->size; i--) {
            uint8_t *addr2 = (uint8_t*) ((ms->buf[direction])+i);
            if (likely(memcmp(addr2, addr, sizeof(MacAddr)) == 0)) {
                return 0;
            }
        }
    }
    memcpy(ms->buf[direction] + ms->last[direction], addr, sizeof(MacAddr));
    ms->last[direction]++;
    return 0;
}

int MacSetForEach(MacSet *ms, MacSetIteratorFunc func, void *data)
{
    unsigned long i = 0;
    if (ms == NULL)
        return 0;
    for (i = 0; i < ms->last[TOSERVER]; i++) {
        int ret = func((uint8_t*) ms->buf[TOSERVER][i], TOSERVER, data);
        if (unlikely(ret != 0)) {
            return ret;
        }
    }
    for (i = 0; i < ms->last[TOCLIENT]; i++) {
        int ret = func((uint8_t*) ms->buf[TOCLIENT][i], TOCLIENT, data);
        if (unlikely(ret != 0)) {
            return ret;
        }
    }
    return 0;
}

unsigned long MacSetSize(MacSet *ms) {
    if (ms == NULL)
        return 0;
    return ms->last[TOCLIENT] + ms->last[TOSERVER];
}

void MacSetReset(MacSet *ms) {
    if (ms == NULL)
        return;
    ms->last[TOCLIENT] = 0;
    ms->last[TOSERVER] = 0;
}

void MacSetFree(MacSet *ms)
{
    if (ms == NULL)
        return;
    SCFree(ms->buf[TOSERVER]);
    SCFree(ms->buf[TOCLIENT]);
    SCFree(ms);
}