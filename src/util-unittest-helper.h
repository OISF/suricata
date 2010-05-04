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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef __UTIL_UNITTEST_HELPER__
#define __UTIL_UNITTEST_HELPER__

Packet *UTHBuildPacketReal(uint8_t *, uint16_t, uint16_t, char *, char *, uint16_t, uint16_t);
Packet *UTHBuildPacket(uint8_t *, uint16_t, uint16_t);
Packet *UTHBuildPacketSrcDst(uint8_t *, uint16_t, uint16_t, char *, char *);
Packet *UTHBuildPacketSrcDstPorts(uint8_t *, uint16_t, uint16_t, uint16_t, uint16_t);

Packet *UTHBuildPacketIPV6SrcDst(uint8_t *, uint16_t, uint16_t, char *, char *);

int UTHPacketMatchSigMpm(Packet *, char *, uint16_t);
Packet **UTHBuildPacketArrayFromEth(uint8_t **, int *, int);
Packet *UTHBuildPacketFromEth(uint8_t *, uint16_t);

void UTHFreePacket(Packet *);
void UTHFreePackets(Packet **, int);

int UTHAppendSigs(DetectEngineCtx *, char **, int);
int UTHMatchPackets(DetectEngineCtx *, Packet **, int);
int UTHPacketMatchSig(Packet *p, char *);
int UTHCheckPacketMatch(Packet *, uint32_t *, uint32_t *, int);

int UTHCheckPacketMatchResults(Packet *, uint32_t *, uint32_t *, int);
int UTHMatchPacketsWithResults(DetectEngineCtx *, Packet **, int, uint32_t *, uint32_t *, int);
int UTHGenericTest(Packet **, int, char **, uint32_t *, uint32_t *, int);

void UTHRegisterTests(void);

#endif /* __UTIL_UNITTEST_HELPER__ */
