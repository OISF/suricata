/* Copyright (C) 2016-2024 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 */

#ifndef SURICATA_UTIL_LOG_REDIS_H
#define SURICATA_UTIL_LOG_REDIS_H

#ifdef HAVE_LIBHIREDIS
#include <hiredis/hiredis.h>


#ifdef HAVE_LIBEVENT
#include <hiredis/async.h>
#endif /* HAVE_LIBEVENT */

#include "conf.h"            /* ConfNode   */

enum RedisMode { REDIS_LIST, REDIS_CHANNEL };

typedef struct RedisSetup_ {
    enum RedisMode mode;
    const char *format;
    const char *command;
    const char *key;
    const char *username;
    const char *password;
    const char *server;
    uint16_t  port;
    int is_async;
    int  batch_size;
    char *stream_format;
} RedisSetup;

#if HAVE_LIBEVENT
enum RedisConnState {
    /** The context is not connected to the Redis server. */
    REDIS_STATE_DISCONNECTED,

    /** The ECHO command failed, possibly due to requiring authentication. */
    REDIS_STATE_ECHO_FAILED,

    /** A connection to the Redis server has been established.
     *  If authentication is not required, this is the final state where data can be safely sent.
     *  If authentication is required, the client must proceed to authenticate before sending data.
     */
    REDIS_STATE_CONNECTED,

    /** Authentication with the Redis server failed. */
    REDIS_STATE_AUTH_FAILED,

    /** The connection is fully authenticated, and ready to send data. */
    REDIS_STATE_AUTHENTICATED,
};
#endif /* HAVE_LIBEVENT */

typedef struct SCLogRedisContext_ {
    redisContext *sync;
#if HAVE_LIBEVENT
    redisAsyncContext *async;
    struct event_base *ev_base;
    enum RedisConnState state;
#endif /* HAVE_LIBEVENT */
    time_t tried;
    int  batch_count;
    time_t last_push;
} SCLogRedisContext;

void SCLogRedisInit(void);
int SCConfLogOpenRedis(SCConfNode *, void *);
int LogFileWriteRedis(void *, const char *, size_t);

#endif /* HAVE_LIBHIREDIS */
#endif /* SURICATA_UTIL_LOG_REDIS_H */
