/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/*
 * Program defines
 *
 *
 */

#ifndef __VIPS_H__
#define __VIPS_H__

#include "packet-queue.h"

/* maximum number of simultanious threads. */
#define NUM_THREADS 256
/* max packets processed simultaniously */
#define MAX_PENDING 512

#define TRUE   1
#define FALSE  0

/* number of packets in processing right now
 * This is the diff between recv'd and verdicted
 * pkts */
u_int32_t pending;
#ifdef DBG_PERF
u_int32_t dbg_maxpending;
#endif /* DBG_PERF */
pthread_mutex_t mutex_pending;
pthread_cond_t cond_pending;

/* preallocated packet structures here */
PacketQueue packet_q;
/* queue's between various other threads */
PacketQueue trans_q[256];

/* uppercase to lowercase conversion lookup table */
u_int8_t g_u8_lowercasetable[256];
/* marco to do the actual lookup */
#define u8_tolower(c) g_u8_lowercasetable[(c)]
// these 2 are slower:
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? g_u8_lowercasetable[(c)] : (c)
//#define u8_tolower(c) ((c) >= 'A' && (c) <= 'Z') ? ((c) + ('a' - 'A')) : (c)


#endif /* __VIPS_H__ */

