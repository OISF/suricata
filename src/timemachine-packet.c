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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */


/**
 * \file
 *
 * \author Mat Oldham <mat.oldham@gmail.com>
 *
 * Packet related functions for usage within TimeMachine
 */
#include "suricata-common.h"
#include "timemachine.h"
#include "timemachine-packet.h"
 
TimeMachinePacket* TimeMachinePacketNew() {

    TimeMachinePacket* packet = SCMalloc(sizeof(TimeMachinePacket));
    
    if (packet == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for packet.");
        exit(EXIT_FAILURE);
    }

    return packet;
}

void TimeMachinePacketDestroy(TimeMachinePacket* packet) {
        
    if (packet == NULL) {
        return;
    }
    
    SCFree(packet);
}