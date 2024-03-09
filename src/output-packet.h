/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Packet Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_PACKET_H
#define SURICATA_OUTPUT_PACKET_H

/** packet logger function pointer type */
typedef int (*PacketLogger)(ThreadVars *, void *thread_data, const Packet *);

/** packet logger condition function pointer type,
 *  must return true for packets that should be logged
 */
typedef bool (*PacketLogCondition)(ThreadVars *, void *thread_data, const Packet *);

int OutputRegisterPacketLogger(LoggerId logger_id, const char *name,
    PacketLogger LogFunc, PacketLogCondition ConditionFunc, OutputCtx *,
    ThreadInitFunc, ThreadDeinitFunc, ThreadExitPrintStatsFunc);

void OutputPacketLoggerRegister(void);

void OutputPacketShutdown(void);

#endif /* SURICATA_OUTPUT_PACKET_H */
