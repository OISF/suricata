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
