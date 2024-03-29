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
 */

#ifndef SURICATA_TM_QUEUES_H
#define SURICATA_TM_QUEUES_H

#include "packet-queue.h"

typedef struct Tmq_ {
    char *name;
    bool is_packet_pool;
    uint16_t id;
    uint16_t reader_cnt;
    uint16_t writer_cnt;
    PacketQueue *pq;
    TAILQ_ENTRY(Tmq_) next;
} Tmq;

Tmq* TmqCreateQueue(const char *name);
Tmq* TmqGetQueueByName(const char *name);

void TmqDebugList(void);
void TmqResetQueues(void);
void TmValidateQueueState(void);

#endif /* SURICATA_TM_QUEUES_H */
