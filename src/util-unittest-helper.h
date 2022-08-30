/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#if defined(UNITTESTS) || defined(FUZZ)
Flow *TestHelperBuildFlow(int family, const char *src, const char *dst, Port sp, Port dp);
int TestHelperBufferToFile(const char *name, const uint8_t *data, size_t size);
#endif
#ifdef UNITTESTS
uint32_t UTHSetIPv4Address(const char *);

Packet *UTHBuildPacketReal(uint8_t *, uint16_t, uint8_t ipproto, const char *, const char *, uint16_t, uint16_t);
Packet *UTHBuildPacket(uint8_t *, uint16_t, uint8_t ipproto);
Packet *UTHBuildPacketSrcDst(uint8_t *, uint16_t, uint8_t ipproto, const char *, const char *);
Packet *UTHBuildPacketSrcDstPorts(uint8_t *, uint16_t, uint8_t ipproto, uint16_t, uint16_t);

Packet *UTHBuildPacketIPV6SrcDst(uint8_t *, uint16_t, uint8_t ipproto, const char *, const char *);

int UTHPacketMatchSigMpm(Packet *, char *, uint16_t);
Packet **UTHBuildPacketArrayFromEth(uint8_t **, int *, int);
Packet *UTHBuildPacketFromEth(uint8_t *, uint16_t);

void UTHFreePacket(Packet *);
void UTHFreePackets(Packet **, int);

void UTHAssignFlow(Packet *p, Flow *f);
Flow *UTHBuildFlow(int family, const char *src, const char *dst, Port sp, Port dp);
void UTHFreeFlow(Flow *flow);
int UTHAddStreamToFlow(Flow *f, int direction, uint8_t *data, uint32_t data_len);
int UTHAddSessionToFlow(Flow *f, uint32_t ts_isn, uint32_t tc_isn);
int UTHRemoveSessionFromFlow(Flow *f);

int UTHAppendSigs(DetectEngineCtx *, const char **, int);
int UTHMatchPackets(DetectEngineCtx *, Packet **, int);
int UTHPacketMatchSig(Packet *p, const char *);
int UTHCheckPacketMatch(Packet *, uint32_t *, uint32_t *, int);

int UTHCheckPacketMatchResults(Packet *, uint32_t *, uint32_t *, int);
int UTHMatchPacketsWithResults(DetectEngineCtx *, Packet **, int, uint32_t *, uint32_t *, int);
int UTHGenericTest(Packet **, int, const char **, uint32_t *, uint32_t *, int);

uint32_t UTHBuildPacketOfFlows(uint32_t, uint32_t, uint8_t);
Packet *UTHBuildPacketIPV6Real(uint8_t *, uint16_t , uint8_t ipproto, const char *, const char *,
                           uint16_t , uint16_t );

void * UTHmemsearch(const void *big, size_t big_len, const void *little, size_t little_len);
int UTHParseSignature(const char *str, bool expect);
#endif

void UTHRegisterTests(void);

#endif /* __UTIL_UNITTEST_HELPER__ */
