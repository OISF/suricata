/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Master Queue Handler
 */

#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"
#include "tmqh-simple.h"
#include "tmqh-nfq.h"
#include "tmqh-packetpool.h"
#include "tmqh-flow.h"

void TmqhSetup (void)
{
    memset(&tmqh_table, 0, sizeof(tmqh_table));

    TmqhSimpleRegister();
    TmqhNfqRegister();
    TmqhPacketpoolRegister();
    TmqhFlowRegister();
}

/** \brief Clean up registration time allocs */
void TmqhCleanup(void)
{
}

Tmqh* TmqhGetQueueHandlerByName(const char *name)
{
    int i;

    for (i = 0; i < TMQH_SIZE; i++) {
        if (strcmp(name, tmqh_table[i].name) == 0)
            return &tmqh_table[i];
    }

    return NULL;
}

