/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#include "tm-threads.h"
#include "decode.h"

/**
 * \brief Packet logger function pointer type.
 */
typedef int (*PacketLogger)(ThreadVars *, void *thread_data, const Packet *);

/**
 * \brief Packet logger condition function point type.
 *
 * Must return true for the packet to be passed onto the packet
 *     logger.
 */
typedef bool (*PacketLogCondition)(ThreadVars *, void *thread_data, const Packet *);

/** \brief Register a packet logger.
 *
 * \param logger_id An ID used to distinguish this logger from others
 *     while profiling.
 * \param name An informational name for this logger. Used only for
 *     debugging.
 * \param LogFunc A function that will be called to log each packet
 *     that passes the condition test.
 * \param ConditionFunc A function to test if the packet should be passed to
 *     the logging function.
 * \param initdata Initialization data that will pass to the
 *     ThreadInitFunc.
 * \param ThreadInitFunc Thread initialization function.
 * \param ThreadDeinitFunc Thread de-initialization function.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCOutputRegisterPacketLogger(LoggerId logger_id, const char *name, PacketLogger LogFunc,
        PacketLogCondition ConditionFunc, void *initdata, ThreadInitFunc, ThreadDeinitFunc);

/** Internal function: private API. */
void OutputPacketLoggerRegister(void);

/** Internal function: private API. */
void OutputPacketShutdown(void);

#endif /* SURICATA_OUTPUT_PACKET_H */
