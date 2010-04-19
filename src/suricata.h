/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/*
 * Program defines
 *
 *
 */

#ifndef __SURICATA_H__
#define __SURICATA_H__

#include "suricata-common.h"
#include "packet-queue.h"

/* the name of our binary */
#define PROG_NAME "Suricata"
#define PROG_VER "0.8.2"

/* number of packets in processing right now
 * This is the diff between recv'd and verdicted
 * pkts
 * XXX this should be turned into an api located
 * in the packetpool code
 */
intmax_t pending;
#ifdef DBG_PERF
uint32_t dbg_maxpending;
#endif /* DBG_PERF */
SCMutex mutex_pending;
SCCondT cond_pending;


/* Run mode */
enum {
    MODE_UNKNOWN = 0,
    MODE_PCAP_DEV,
    MODE_PCAP_FILE,
    MODE_PFRING,
    MODE_NFQ,
    MODE_IPFW,
    MODE_UNITTEST
};

/* preallocated packet structures here
 * XXX move to the packetpool queue handler code
 */
PacketQueue packet_q;
/* queue's between various other threads
 * XXX move to the TmQueue structure later
 */
PacketQueue trans_q[256];
/* memset to zeros, and mutex init! */
void GlobalInits();

/* uppercase to lowercase conversion lookup table */
uint8_t g_u8_lowercasetable[256];
/* marco to do the actual lookup */
#define u8_tolower(c) g_u8_lowercasetable[(c)]
// these 2 are slower:
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? g_u8_lowercasetable[(c)] : (c)
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c)

void EngineStop(void);
void EngineKill(void);

int RunmodeIsUnittests(void);

#endif /* __SURICATA_H__ */

