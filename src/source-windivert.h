/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 *
 * \file
 *
 * \author Jacob Masen-Smith <jacob@evengx.com>
 *
 */

#ifndef __SOURCE_WINDIVERT_H__
#define __SOURCE_WINDIVERT_H__

#ifdef WINDIVERT

#include "windivert.h"

#define WINDIVERT_FILTER_MAXLEN 128 /* from windivert_device.h */

typedef void *WinDivertHandle;

/**
 * \brief WinDivertQueueVars is the queue configuration and other miscellaneous
 * information about the specific queue/filter.
 *
 * see https://reqrypt.org/windivert-doc.html#divert_open for more info
 */
typedef struct WinDivertQueueVars_
{
    int queue_num;

    /* see https://reqrypt.org/windivert-doc.html#filter_language */
    char filter_str[WINDIVERT_FILTER_MAXLEN + 1];
    WINDIVERT_LAYER layer;
    int16_t priority;
    uint64_t flags;

    WinDivertHandle filter_handle;
    /* only needed for setup/teardown; Recv/Send are internally synchronized */
    SCMutex filter_init_mutex;

    /* counters */
    uint32_t pkts;
    uint64_t bytes;
    uint32_t errs;
    uint32_t accepted;
    uint32_t dropped;
    uint32_t replaced;
    SCMutex counters_mutex;
} WinDivertQueueVars;

typedef struct WinDivertPacketVars_
{
    int thread_num;

    WINDIVERT_ADDRESS addr;
    bool verdicted;
} WinDivertPacketVars;

int WinDivertRegisterQueue(bool forward, char *filter_str);
void *WinDivertGetThread(int thread);
void *WinDivertGetQueue(int queue);

void SourceWinDivertRegisterTests(void);

#endif /* WINDIVERT */
#endif /* __SOURCE_WINDIVERT_H__ */