/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * Foundation, Inc., 51 Fraznklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */


/**
 * \file
 *
 * \author Mat Oldham <mat.oldham@gmail.com>
 *
 * Provides packet related data structures required for the timemachine module 
 */
 
#ifndef __TIMEMACHINE_PACKET_H__
#define __TIMEMACHINE_PACKET_H__

#include "suricata-common.h"
#include "timemachine.h"

struct TimeMachinePackets_;

struct TimeMachinePacket_ {
    struct Flow_                            *flow;
    struct pcap_pkthdr                      header;
    void                                    *data;
    TAILQ_ENTRY(TimeMachinePacket_)         next;
};

/* TAILQ Macros */
TAILQ_HEAD(TimeMachinePackets_, TimeMachinePacket_);

TimeMachinePacket* TimeMachinePacketNew();
void TimeMachinePacketDestroy(TimeMachinePacket*);

#endif /* __TIMEMACHINE_PACKET_H__ */
