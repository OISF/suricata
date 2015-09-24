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
 * Provides output related data structures required for the timemachine module 
 */

#ifndef __TIMEMACHINE_OUTPUT_H__
#define __TIMEMACHINE_OUTPUT_H__

#include "suricata-common.h"
#include "timemachine.h"

struct TimeMachineOutput_ {
    pcap_t                                    *pcap_out;
    pcap_dumper_t                             *pcap_dumper;
    FILE                                      *output_file;

    TimeMachineFlow                           *flow;

    struct timeval                            updated;
    TAILQ_ENTRY(TimeMachineOutput_)           next;     
};
 
TimeMachineOutput* TimeMachineOutputNew(TimeMachineFlow*);
void TimeMachineOutputDestroy(TimeMachineOutput*);

#endif /* __TIMEMACHINE_OUTPUT_H__ */
