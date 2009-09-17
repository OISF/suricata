/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/**
 * Common includes, etc.
 */

#ifndef __EIDPS_COMMON_H__
#define __EIDPS_COMMON_H__

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
#include <pthread.h>

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

#endif /* __EIDPS_COMMON_H__ */

