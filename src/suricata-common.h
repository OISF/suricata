/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/**
 * Common includes, etc.
 */

#ifndef __SURICATA_COMMON_H__
#define __SURICATA_COMMON_H__

#define TRUE   1
#define FALSE  0

#include <sys/types.h> /* for gettid(2) */
#define _GNU_SOURCE
#define __USE_GNU
#include <sys/syscall.h>
#include <sched.h>     /* for sched_setaffinity(2) */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>

#include <pcre.h>
#include "threads.h"

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#define BUG_ON(x) assert(!(x))

/** type for the internal signature id. Since it's used in the matching engine
 *  extensively keeping this as small as possible reduces the overall memory
 *  footprint of the engine. Set to uint32_t if the engine needs to support
 *  more than 64k sigs. */
#define SigIntId uint16_t
//#define SigIntId uint32_t

#endif /* __SURICATA_COMMON_H__ */

