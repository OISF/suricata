/* vi: set et ts=4: */
/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 *
 * File-like output for logging:  redis
 */
#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "util-logopenfile-redis.h"
#include "util-logopenfile.h"

#ifdef HAVE_LIBHIREDIS

#ifdef HAVE_LIBEVENT
#include <hiredis/adapters/libevent.h>
#endif /* HAVE_LIBEVENT */

const char * redis_push_cmd = "LPUSH";
const char * redis_publish_cmd = "PUBLISH";

/** \brief SCLogRedisContextAlloc() - Allocates and initalizes redis context
 *  \param async indicates that async mode will be used
 *  \retval SCLogRedisContext * pointer if succesful, EXIT_FAILURE program if not
 */
static SCLogRedisContext * SCLogRedisContextAlloc(int async)
{
    SCLogRedisContext* ctx = (SCLogRedisContext*) SCMalloc(sizeof(SCLogRedisContext));
    if (unlikely(ctx == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate redis context");
        exit(EXIT_FAILURE);
    }
    ctx->sync = NULL;
#if HAVE_LIBEVENT
    ctx->ev_base = NULL;
    ctx->async   = NULL;
    if (async) {
        ctx->ev_base = event_base_new();
        if (unlikely(ctx->ev_base == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate redis async event base");
            exit(EXIT_FAILURE);
        }
    }
#endif
    return ctx;
}

/** \brief SCLogRedisContextFree() free redis context
 *  \param async indicates that async mode was used
 */
void SCLogRedisContextFree(SCLogRedisContext *ctx, int async)
{
    if (ctx == NULL) {
        return;
    }
#if HAVE_LIBEVENT
    if (async) {
        if (ctx->ev_base != NULL) {
            event_base_free(ctx->ev_base);
        }
    }
#endif
    SCFree(ctx);
}

static int SCConfLogReopenRedis(LogFileCtx *log_ctx);

#if HAVE_LIBEVENT

#if HIREDIS_MAJOR == 0 && HIREDIS_MINOR < 11

/** \brief RedisConnectCallback() Closes redis log more
 *  \param c redis async context
 */
void RedisConnectCallback(const redisAsyncContext *c)
{
	SCLogInfo("Connected to redis server.");
}
#else

/** \brief RedisConnectCallback() Closes redis log more
 *  \param c redis async context
 *  \param status status reported by async caller
 */
void RedisConnectCallback(const redisAsyncContext *c, int status)
{
	SCLogInfo("Connected to redis server. Status [%d]", status);
}

#endif // HIREDIS_MAJOR == 0 && HIREDIS_MINOR < 11

/** \brief RedisDisconnectCallback() Callback when disconnection from redis happens.
 *  \param c redis async context
 *  \param status status reported by async caller
 */
void RedisDisconnectCallback(const redisAsyncContext *c, int status)
{
	SCLogInfo("Disconnected from redis server. Status [%d]", status);
}


/** \brief SCRedisAsyncCommandCallback() Callback when reply from redis happens.
 *  \param c redis async context
 *  \param r redis reply
 *  \param privvata opaque datq with pointer to LogFileCtx
 */
static void SCRedisAsyncCommandCallback (redisAsyncContext *async, void *r, void *privdata)
{
    LogFileCtx *file_ctx = privdata;
    redisReply *reply = r;
    /* Disconnection or lost reply may have happened */
    if (reply == NULL) {
        SCConfLogReopenRedis(file_ctx);
    }
}

#endif // HAVE_LIBEVENT

/** \brief SCConfLogReopenRedis() Open or re-opens connection to redis for logging.
 *  \param log_ctx Log file context allocated by caller
 */
static int SCConfLogReopenRedis(LogFileCtx *log_ctx)
{
	/* only try to reconnect once per second */
	if (log_ctx->redis_setup.tried >= time(NULL)) {
		return -1;
	}
	SCLogRedisContext * ctx = log_ctx->redis;
	const char *redis_server = log_ctx->redis_setup.server;
	int redis_port = log_ctx->redis_setup.port;
#if HAVE_LIBEVENT
    /* ASYNC */
    if (log_ctx->redis_setup.async) {
        if (ctx->ev_base != NULL) {
            event_base_loopbreak(ctx->ev_base);
        }
        if (ctx->async != NULL)  {
            redisAsyncFree(ctx->async);
        }
        ctx->async = redisAsyncConnect(redis_server, redis_port);
        if ( ctx->async != NULL && ctx->async->err) {
            SCLogError(SC_ERR_SOCKET, "Error connecting to redis server: [%s]", ctx->async->errstr);
            redisAsyncFree(ctx->async);
            ctx->async = NULL;
            log_ctx->redis_setup.tried = time(NULL);
            return -1;
        }
        if (ctx->async != NULL)  {
            redisLibeventAttach(ctx->async,ctx->ev_base);
            redisAsyncSetConnectCallback(ctx->async,RedisConnectCallback);
            redisAsyncSetDisconnectCallback(ctx->async,RedisDisconnectCallback);
            redisAsyncHandleWrite(ctx->async);
        }
    } else
#endif
	{
        /* SYNCHRONOUS */
        if (ctx->sync != NULL)  {
            redisFree(ctx->sync);
        }
        ctx->sync = redisConnect(redis_server, redis_port);
        if (ctx->sync != NULL && ctx->sync->err) {
            SCLogError(SC_ERR_SOCKET, "Error connecting to redis server: [%s]", ctx->sync->errstr);
            redisFree(ctx->sync);
            ctx->sync = NULL;
            log_ctx->redis_setup.tried = time(NULL);
            return -1;
        }
    }
    log_ctx->redis = ctx;
    log_ctx->redis_setup.tried = 0;
    log_ctx->redis_setup.batch_count = 0;
    return 0;
}

/** \brief SCLogFileCloseRedis() Closes redis log more
 *  \param log_ctx Log file context allocated by caller
 */
static void SCLogFileCloseRedis(LogFileCtx *log_ctx)
{
    SCLogRedisContext * ctx = log_ctx->redis;
    if ( ctx == NULL) {
        return;
    }
    /* asynchronous */
    if (log_ctx->redis_setup.async) {
#if HAVE_LIBEVENT == 1
        if (ctx->async != NULL) {
            redisAsyncFree(ctx->async);
        }
        if (ctx->ev_base) {
            event_base_loopbreak(ctx->ev_base);
        }
        ctx->async = NULL;
#endif
    } else {
        /* synchronous */
        if (ctx->sync) {
            redisReply *reply;
            int i;
            for (i = 0; i < log_ctx->redis_setup.batch_count; i++) {
                redisGetReply(ctx->sync, (void **)&reply);
                if (reply)
                    freeReplyObject(reply);
            }
            redisFree(ctx->sync);
            ctx->sync = NULL;
        }
        log_ctx->redis_setup.tried = 0;
        log_ctx->redis_setup.batch_count = 0;
    }
}

/** \brief configure and initializes redis output logging
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \retval 0 on success
 */
int SCConfLogOpenRedis(ConfNode *redis_node, void *lf_ctx)
{
    LogFileCtx *log_ctx = lf_ctx;

    const char *redis_server = NULL;
    const char *redis_port = NULL;
    const char *redis_mode = NULL;
    const char *redis_key = NULL;
    int async = 0;

    if (redis_node) {
        redis_server = ConfNodeLookupChildValue(redis_node, "server");
        redis_port =  ConfNodeLookupChildValue(redis_node, "port");
        redis_mode =  ConfNodeLookupChildValue(redis_node, "mode");
        redis_key =  ConfNodeLookupChildValue(redis_node, "key");
    }
    if (!redis_server) {
        redis_server = "127.0.0.1";
        SCLogInfo("Using default redis server (127.0.0.1)");
    }
    if (!redis_port)
        redis_port = "6379";
    if (!redis_mode)
        redis_mode = "list";
    if (!redis_key)
        redis_key = "suricata";
    log_ctx->redis_setup.key = SCStrdup(redis_key);
    ConfGetChildValueBool(redis_node, "async", &async);
    log_ctx->redis_setup.async = async;
#ifndef HAVE_LIBEVENT 
    if (async) {
        SCLogWarning(SC_ERR_NO_LIBEVENT, "async option not available.");
    }
    log_ctx->redis_setup.async = 0;
#endif //ifndef HAVE_LIBEVENT
    if (!log_ctx->redis_setup.key) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate redis key name");
        exit(EXIT_FAILURE);
    }
    log_ctx->redis_setup.batch_size = 0;
    ConfNode *pipelining = ConfNodeLookupChild(redis_node, "pipelining");
    if (pipelining) {
        int enabled = 0;
        int ret;
        intmax_t val;
        ret = ConfGetChildValueBool(pipelining, "enabled", &enabled);
        if (ret && enabled) {
            ret = ConfGetChildValueInt(pipelining, "batch-size", &val);
            if (ret) {
                log_ctx->redis_setup.batch_size = val;
            } else {
                log_ctx->redis_setup.batch_size = 10;
            }
        }
    }
    if (!strcmp(redis_mode, "list")) {
        log_ctx->redis_setup.command = redis_push_cmd;
        if (!log_ctx->redis_setup.command) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate redis key command");
            exit(EXIT_FAILURE);
        }
    } else {
        log_ctx->redis_setup.command = redis_publish_cmd;
        if (!log_ctx->redis_setup.command) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate redis key command");
            exit(EXIT_FAILURE);
        }
    }
    /* store server params for reconnection */
    log_ctx->redis_setup.server = SCStrdup(redis_server);
    if (!log_ctx->redis_setup.server) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating redis server string");
        exit(EXIT_FAILURE);
    }
    log_ctx->redis_setup.port = atoi(redis_port);
    log_ctx->redis_setup.tried = 0;
    log_ctx->redis = SCLogRedisContextAlloc(async);
    SCConfLogReopenRedis(log_ctx);
    log_ctx->Close = SCLogFileCloseRedis;

    return 0;
}

/** \brief SCLogRedisWriteAsync() writes string to redis output in async mode
 *  \param file_ctx Log file context allocated by caller
 *  \param string Buffer to output
 */
static void SCLogRedisWriteAsync(LogFileCtx *file_ctx, const char *string)
{
    SCLogRedisContext * ctx = file_ctx->redis;
    redisAsyncContext * redis_async = ctx->async;

    if (unlikely(redis_async == NULL)) {
        return;
    }

    redisAsyncCommand(redis_async,
            SCRedisAsyncCommandCallback,
            file_ctx,
            "%s %s %s",
            file_ctx->redis_setup.command,
            file_ctx->redis_setup.key,
            string);

    event_base_loop(ctx->ev_base, EVLOOP_NONBLOCK);
}

/** \brief SCLogRedisWriteSync() writes string to redis output in sync mode
 *  \param file_ctx Log file context allocated by caller
 *  \param string Buffer to output
 */
static void SCLogRedisWriteSync(LogFileCtx *file_ctx, const char *string)
{
    SCLogRedisContext * ctx = file_ctx->redis;
    redisContext *redis = ctx->sync;
    if (unlikely(redis == NULL)) {
        SCConfLogReopenRedis(file_ctx);
    }
    /* synchronous mode */
    if (file_ctx->redis_setup.batch_size) {
        redisAppendCommand(redis, "%s %s %s",
                file_ctx->redis_setup.command,
                file_ctx->redis_setup.key,
                string);
        if (file_ctx->redis_setup.batch_count == file_ctx->redis_setup.batch_size) {
            redisReply *reply;
            int i;
            file_ctx->redis_setup.batch_count = 0;
            for (i = 0; i <= file_ctx->redis_setup.batch_size; i++) {
                if (redisGetReply(redis, (void **)&reply) == REDIS_OK) {
                    freeReplyObject(reply);
                } else {
                    if (redis->err) {
                        SCLogInfo("Error when fetching reply: %s (%d)",
                                redis->errstr,
                                redis->err);
                    }
                    switch (redis->err) {
                        case REDIS_ERR_EOF:
                        case REDIS_ERR_IO:
                            SCLogInfo("Reopening connection to redis server");
                            SCConfLogReopenRedis(file_ctx);
                            if (file_ctx->redis) {
                                SCLogInfo("Reconnected to redis server");
                                return;
                            } else {
                                SCLogInfo("Unable to reconnect to redis server");
                                return;
                            }
                            break;
                        default:
                            SCLogWarning(SC_ERR_INVALID_VALUE,
                                    "Unsupported error code %d",
                                    redis->err);
                            return;
                    }
                }
            }
        } else {
            file_ctx->redis_setup.batch_count++;
        }
    } else {
        redisReply *reply = redisCommand(redis, "%s %s %s",
                file_ctx->redis_setup.command,
                file_ctx->redis_setup.key,
                string);
        /* We may lose the reply if disconnection happens*/
        if (reply) {
            switch (reply->type) {
                case REDIS_REPLY_ERROR:
                    SCLogWarning(SC_ERR_SOCKET, "Redis error: %s", reply->str);
                    SCConfLogReopenRedis(file_ctx);
                    break;
                case REDIS_REPLY_INTEGER:
                    SCLogDebug("Redis integer %lld", reply->integer);
                    break;
                default:
                    SCLogError(SC_ERR_INVALID_VALUE,
                            "Redis default triggered with %d", reply->type);
                    SCConfLogReopenRedis(file_ctx);
                    break;
            }
            freeReplyObject(reply);
        } else {
            SCConfLogOpenRedis(file_ctx);
        }
    }
}

/**
 * \brief LogFileWriteRedis() writes log data to redis output.
 * \param log_ctx Log file context allocated by caller
 * \param string buffer with data to write
 * \param string_len data length
 * \retval 0 on sucess;
 * \retval -1 on failure;
 */
int LogFileWriteRedis(void *lf_ctx, const char *string, size_t string_len)
{
    LogFileCtx *file_ctx = lf_ctx;
    if (file_ctx->redis == NULL) {
        SCConfLogReopenRedis(file_ctx);
        if (file_ctx->redis == NULL) {
            return -1;
        } else {
            SCLogInfo("Reconnected to redis server");
        }
    }
#if HAVE_LIBEVENT
	/* async mode on */
    if (file_ctx->redis_setup.async) {
        SCLogRedisWriteAsync(file_ctx, string);
        return 0;
    } 
#endif
    /* sync mode */
    SCLogRedisWriteSync(file_ctx, string);
    return 0;
}
#endif //#ifdef HAVE_LIBHIREDIS
