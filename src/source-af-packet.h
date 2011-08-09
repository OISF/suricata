/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __SOURCE_AFP_H__
#define __SOURCE_AFP_H__

#ifndef HAVE_PACKET_FANOUT /* not defined if linux/if_packet.h trying to force */
#define HAVE_PACKET_FANOUT 1

#define PACKET_FANOUT                  18

#define PACKET_FANOUT_HASH             0
#define PACKET_FANOUT_LB               1
#define PACKET_FANOUT_CPU              2
#define PACKET_FANOUT_FLAG_DEFRAG      0x8000

#endif /* HAVE_PACKET_FANOUT */

void TmModuleReceiveAFPRegister (void);
void TmModuleDecodeAFPRegister (void);
int AFPConfGetThreads();

#endif /* __SOURCE_AFP_H__ */
