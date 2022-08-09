/* vi: set et ts=4: */
/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#include "util-log-redis.h"
#include "util-logopenfile.h"
#include "util-byte.h"

#ifdef HAVE_LIBHIREDIS

#ifdef HAVE_LIBEVENT_PTHREADS
#include <event2/thread.h>
#endif /* HAVE_LIBEVENT_PTHREADS */

static const char * redis_lpush_cmd = "LPUSH";
static const char * redis_rpush_cmd = "RPUSH";
static const char * redis_publish_cmd = "PUBLISH";
static const char * redis_default_key = "suricata";
static const char * redis_default_server = "127.0.0.1";

static int SCConfLogReopenSyncRedis(LogFileCtx *log_ctx);
static void SCLogFileCloseRedis(LogFileCtx *log_ctx);

/**
 * \brief SCLogRedisInit() - Initializes global stuff before threads
 */
void SCLogRedisInit()
{
#ifdef HAVE_LIBEVENT_PTHREADS
    evthread_use_pthreads();
#endif /* HAVE_LIBEVENT_PTHREADS */
}

/** \brief SCLogRedisContextAlloc() - Allocates and initializes redis context
 */
static SCLogRedisContext *SCLogRedisContextAlloc(void)
{
    SCLogRedisContext* ctx = (SCLogRedisContext*) SCCalloc(1, sizeof(SCLogRedisContext));
    if (ctx == NULL) {
        FatalError(SC_ERR_FATAL, "Unable to allocate redis context");
    }
    ctx->sync = NULL;
#if HAVE_LIBEVENT
    ctx->ev_base = NULL;
    ctx->async   = NULL;
#endif
    ctx->batch_count = 0;
    ctx->last_push = 0;
    ctx->tried = 0;

    return ctx;
}

#ifdef HAVE_LIBEVENT

static int SCConfLogReopenAsyncRedis(LogFileCtx *log_ctx);
#include <hiredis/adapters/libevent.h>

/** \brief SCLogRedisAsyncContextAlloc() - Allocates and initalizes redis context with async
 */
static SCLogRedisContext *SCLogRedisContextAsyncAlloc(void)
{
    SCLogRedisContext* ctx = (SCLogRedisContext*) SCCalloc(1, sizeof(SCLogRedisContext));
    if (unlikely(ctx == NULL)) {
        FatalError(SC_ERR_FATAL, "Unable to allocate redis context");
    }

    ctx->sync = NULL;
    ctx->async   = NULL;
    ctx->ev_base = NULL;
    ctx->connected = 0;
    ctx->batch_count = 0;
    ctx->last_push = 0;
    ctx->tried = 0;

    return ctx;
}

/** \brief SCRedisAsyncCommandCallback() Callback when reply from redis happens.
 *  \param ac redis async context
 *  \param r redis reply
 *  \param privdata opaque data with pointer to LogFileCtx
 */
static void SCRedisAsyncCommandCallback(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;
    LogFileCtx *log_ctx = privdata;
    SCLogRedisContext *ctx = log_ctx->redis;

    if (reply == NULL) {
        if (ctx->connected > 0)
            SCLogInfo("Missing reply from redis, disconnected.");
        ctx->connected = 0;
    } else {
        ctx->connected = 1;
        event_base_loopbreak(ctx->ev_base);
    }
}

/** \brief SCRedisAsyncEchoCommandCallback() Callback for an ECHO command reply
 *         This is used to check if redis is connected.
 *  \param ac redis async context
 *  \param r redis reply
 *  \param privdata opaque data with pointer to LogFileCtx
 */
static void SCRedisAsyncEchoCommandCallback(redisAsyncContext *ac, void *r, void *privdata)
{
    redisReply *reply = r;
    SCLogRedisContext * ctx = privdata;

    if (reply) {
       if (ctx->connected == 0) {
          SCLogNotice("Connected to Redis.");
          ctx->connected = 1;
          ctx->tried = 0;
       }
    } else {
       ctx->connected = 0;
       if (ctx->tried == 0) {
          SCLogWarning(SC_ERR_SOCKET, "Failed to connect to Redis... (will keep trying)");
       }
       ctx->tried = time(NULL);
    }
    event_base_loopbreak(ctx->ev_base);
}

/** \brief SCRedisAsyncEchoCommandCallback() Callback for an QUIT command reply
 *         Emits and awaits response for an async ECHO command.
 *         It's used for check if redis is alive.
 *  \param ctx redis context
 */
static void SCLogAsyncRedisSendEcho(SCLogRedisContext * ctx)
{
    redisAsyncCommand(ctx->async, SCRedisAsyncEchoCommandCallback, ctx, "ECHO suricata");
    event_base_dispatch(ctx->ev_base);
}

/** \brief SCRedisAsyncEchoCommandCallback() Callback for an QUIT command reply
 *         This is used to terminate connection with redis.
 *  \param ac redis async context
 *  \param r redis reply
 *  \param privdata opaque data with pointer to LogFileCtx
 */
static void SCRedisAsyncQuitCommandCallback(redisAsyncContext *ac, void *r, void *privdata)
{
    SCLogInfo("Disconnecting from redis!");
}

/** \brief QUIT command
 *         Emits and awaits response for an async QUIT command.
 *         It's used to disconnect with redis
 *  \param ctx redis context
 */
static void SCLogAsyncRedisSendQuit(SCLogRedisContext * ctx)
{
    if (ctx->connected) {
        redisAsyncCommand(ctx->async, SCRedisAsyncQuitCommandCallback, ctx, "QUIT");
        SCLogInfo("QUIT Command sent to redis. Connection will terminate!");
    }

    redisAsyncFree(ctx->async);
    event_base_dispatch(ctx->ev_base);
    ctx->async = NULL;
    event_base_free(ctx->ev_base);
    ctx->ev_base = NULL;
    ctx->connected = 0;
}

/** \brief SCConfLogReopenAsyncRedis() Open or re-opens connection to redis for logging.
 *  \param log_ctx Log file context allocated by caller
 */
static int SCConfLogReopenAsyncRedis(LogFileCtx *log_ctx)
{
    SCLogRedisContext * ctx = log_ctx->redis;
    const char *redis_server = log_ctx->redis_setup.server;
    int redis_port = log_ctx->redis_setup.port;

    /* only try to reconnect once per second */
    if (ctx->tried >= time(NULL)) {
        return -1;
    }

    if (strchr(redis_server, '/') == NULL) {
        ctx->async = redisAsyncConnect(redis_server, redis_port);
    } else {
        ctx->async = redisAsyncConnectUnix(redis_server);
    }

    if (ctx->ev_base != NULL) {
        event_base_free(ctx->ev_base);
        ctx->ev_base = NULL;
    }

    if (ctx->async == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocate redis async.");
        ctx->tried = time(NULL);
        return -1;
    }

    if (ctx->async != NULL && ctx->async->err) {
        SCLogError(SC_ERR_SOCKET, "Error setting to redis async: [%s].", ctx->async->errstr);
        ctx->tried = time(NULL);
        return -1;
    }

    ctx->ev_base = event_base_new();

    if (ctx->ev_base == NULL) {
        ctx->tried = time(NULL);
        redisAsyncFree(ctx->async);
        ctx->async = NULL;
        return -1;
    }

    redisLibeventAttach(ctx->async, ctx->ev_base);

    log_ctx->redis = ctx;
    log_ctx->Close = SCLogFileCloseRedis;
    return 0;
}


/** \brief SCLogRedisWriteAsync() writes string to redis output in async mode
 *  \param file_ctx Log file context allocated by caller
 *  \param string Buffer to output
 */
static int SCLogRedisWriteAsync(LogFileCtx *file_ctx, const char *string, size_t string_len)
{
    SCLogRedisContext *ctx = file_ctx->redis;

    if (! ctx->connected) {
        if (SCConfLogReopenAsyncRedis(file_ctx) == -1) {
            return -1;
        }
        if (ctx->tried == 0) {
           SCLogNotice("Trying to connect to Redis");
        }
        SCLogAsyncRedisSendEcho(ctx);
    }

    if (!ctx->connected) {
        return -1;
    }

    if (ctx->async == NULL) {
        return -1;
    }

    redisAsyncCommand(ctx->async,
            SCRedisAsyncCommandCallback,
            file_ctx,
            "%s %s %s",
            file_ctx->redis_setup.command,
            file_ctx->redis_setup.key,
            string);

    event_base_loop(ctx->ev_base, EVLOOP_NONBLOCK);

    return 0;
}

#endif// HAVE_LIBEVENT

/** \brief SCConfLogReopenSyncRedis() Open or re-opens connection to redis for logging.
 *  \param log_ctx Log file context allocated by caller
 */
static int SCConfLogReopenSyncRedis(LogFileCtx *log_ctx)
{
    SCLogRedisContext * ctx = log_ctx->redis;

    /* only try to reconnect once per second */
    if (ctx->tried >= time(NULL)) {
        return -1;
    }

    const char *redis_server = log_ctx->redis_setup.server;
    int redis_port = log_ctx->redis_setup.port;

    if (ctx->sync != NULL)  {
        redisFree(ctx->sync);
    }

    if (strchr(redis_server, '/') == NULL) {
        ctx->sync = redisConnect(redis_server, redis_port);
    } else {
        ctx->sync = redisConnectUnix(redis_server);
    }
    if (ctx->sync == NULL) {
        SCLogError(SC_ERR_SOCKET, "Error connecting to redis server.");
        ctx->tried = time(NULL);
        return -1;
    }
    if (ctx->sync->err) {
        SCLogError(SC_ERR_SOCKET, "Error connecting to redis server: [%s].", ctx->sync->errstr);
        redisFree(ctx->sync);
        ctx->sync = NULL;
        ctx->tried = time(NULL);
        return -1;
    }
    SCLogInfo("Connected to redis server [%s].", log_ctx->redis_setup.server);

    log_ctx->redis = ctx;
    log_ctx->Close = SCLogFileCloseRedis;
    return 0;
}
/** \brief SCLogRedisWriteSync() writes string to redis output in sync mode
 *  \param file_ctx Log file context allocated by caller
 *  \param string Buffer to output
 */
static int SCLogRedisWriteSync(LogFileCtx *file_ctx, const char *string)
{
    SCLogRedisContext * ctx = file_ctx->redis;
    int ret = -1;
    redisContext *redis = ctx->sync;
    if (redis == NULL) {
        SCConfLogReopenSyncRedis(file_ctx);
        redis = ctx->sync;
        if (redis == NULL) {
            SCLogDebug("Redis after re-open is not available.");
            return -1;
        }
    }

    /* synchronous mode */
    if (file_ctx->redis_setup.batch_size) {
        redisAppendCommand(redis, "%s %s %s",
                file_ctx->redis_setup.command,
                file_ctx->redis_setup.key,
                string);
        time_t now = time(NULL);
        if ((ctx->batch_count == file_ctx->redis_setup.batch_size) || (ctx->last_push < now)) {
            redisReply *reply;
            int i;
            int batch_size = ctx->batch_count;
            ctx->batch_count = 0;
            ctx->last_push = now;
            for (i = 0; i <= batch_size; i++) {
                if (redisGetReply(redis, (void **)&reply) == REDIS_OK) {
                    freeReplyObject(reply);
                    ret = 0;
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
                            SCConfLogReopenSyncRedis(file_ctx);
                            redis = ctx->sync;
                            if (redis) {
                                SCLogInfo("Reconnected to redis server");
                                redisAppendCommand(redis, "%s %s %s",
                                        file_ctx->redis_setup.command,
                                        file_ctx->redis_setup.key,
                                        string);
                                ctx->batch_count++;
                                return 0;
                            } else {
                                SCLogInfo("Unable to reconnect to redis server");
                                return -1;
                            }
                            break;
                        default:
                            SCLogWarning(SC_ERR_INVALID_VALUE,
                                    "Unsupported error code %d",
                                    redis->err);
                            return -1;
                    }
                }
            }
        } else {
            ctx->batch_count++;
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
                    SCConfLogReopenSyncRedis(file_ctx);
                    break;
                case REDIS_REPLY_INTEGER:
                    SCLogDebug("Redis integer %lld", reply->integer);
                    ret = 0;
                    break;
                default:
                    SCLogError(SC_ERR_INVALID_VALUE,
                            "Redis default triggered with %d", reply->type);
                    SCConfLogReopenSyncRedis(file_ctx);
                    break;
            }
            freeReplyObject(reply);
        } else {
            SCConfLogReopenSyncRedis(file_ctx);
        }
    }
    return ret;
}

/**
 * \brief LogFileWriteRedis() writes log data to redis output.
 * \param log_ctx Log file context allocated by caller
 * \param string buffer with data to write
 * \param string_len data length
 * \retval 0 on success;
 * \retval -1 on failure;
 */
int LogFileWriteRedis(void *lf_ctx, const char *string, size_t string_len)
{
    LogFileCtx *file_ctx = lf_ctx;
    if (file_ctx == NULL) {
        return -1;
    }

#if HAVE_LIBEVENT
    /* async mode on */
    if (file_ctx->redis_setup.is_async) {
        return SCLogRedisWriteAsync(file_ctx, string, string_len);
    }
#endif
    /* sync mode */
    if (! file_ctx->redis_setup.is_async) {
        return SCLogRedisWriteSync(file_ctx, string);
    }
    return -1;
}

/** \brief configure and initializes redis output logging
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \retval 0 on success
 */
int SCConfLogOpenRedis(ConfNode *redis_node, void *lf_ctx)
{
    LogFileCtx *log_ctx = lf_ctx;

    if (log_ctx->threaded) {
        FatalError(SC_ERR_FATAL, "redis does not support threaded output");
    }

    const char *redis_port = NULL;
    const char *redis_mode = NULL;

    int is_async = 0;

    if (redis_node) {
        log_ctx->redis_setup.server = ConfNodeLookupChildValue(redis_node, "server");
        log_ctx->redis_setup.key =  ConfNodeLookupChildValue(redis_node, "key");

        redis_port =  ConfNodeLookupChildValue(redis_node, "port");
        redis_mode =  ConfNodeLookupChildValue(redis_node, "mode");

        (void)ConfGetChildValueBool(redis_node, "async", &is_async);
    }
    if (!log_ctx->redis_setup.server) {
        log_ctx->redis_setup.server = redis_default_server;
        SCLogInfo("Using default redis server (127.0.0.1)");
    }
    if (!redis_port)
        redis_port = "6379";
    if (!redis_mode)
        redis_mode = "list";
    if (!log_ctx->redis_setup.key) {
        log_ctx->redis_setup.key = redis_default_key;
    }

#ifndef HAVE_LIBEVENT
    if (is_async) {
        SCLogWarning(SC_ERR_NO_REDIS_ASYNC, "async option not available.");
    }
    is_async = 0;
#endif //ifndef HAVE_LIBEVENT

    log_ctx->redis_setup.is_async = is_async;
    log_ctx->redis_setup.batch_size = 0;
    if (redis_node) {
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
    } else {
        log_ctx->redis_setup.batch_size = 0;
    }

    if (!strcmp(redis_mode, "list") || !strcmp(redis_mode,"lpush")) {
        log_ctx->redis_setup.command = redis_lpush_cmd;
    } else if(!strcmp(redis_mode, "rpush")){
        log_ctx->redis_setup.command = redis_rpush_cmd;
    } else if(!strcmp(redis_mode,"channel") || !strcmp(redis_mode,"publish")) {
        log_ctx->redis_setup.command = redis_publish_cmd;
    } else {
        FatalError(SC_ERR_FATAL, "Invalid redis mode");
    }

    /* store server params for reconnection */
    if (!log_ctx->redis_setup.server) {
        FatalError(SC_ERR_FATAL, "Error allocating redis server string");
    }
    if (StringParseUint16(&log_ctx->redis_setup.port, 10, 0, (const char *)redis_port) < 0) {
        FatalError(SC_ERR_INVALID_VALUE, "Invalid value for redis port: %s", redis_port);
    }
    log_ctx->Close = SCLogFileCloseRedis;

#ifdef HAVE_LIBEVENT
    if (is_async) {
        log_ctx->redis = SCLogRedisContextAsyncAlloc();
    }
#endif /*HAVE_LIBEVENT*/
    if (! is_async) {
        log_ctx->redis = SCLogRedisContextAlloc();
        SCConfLogReopenSyncRedis(log_ctx);
    }
    return 0;
}

/** \brief SCLogFileCloseRedis() Closes redis log more
 *  \param log_ctx Log file context allocated by caller
 */
void SCLogFileCloseRedis(LogFileCtx *log_ctx)
{
    SCLogRedisContext * ctx = log_ctx->redis;
    if (ctx == NULL) {
        return;
    }
    /* asynchronous */
    if (log_ctx->redis_setup.is_async) {
#if HAVE_LIBEVENT == 1
        if (ctx->async) {
            if (ctx->connected > 0) {
                SCLogAsyncRedisSendQuit(ctx);
            }
            if (ctx->ev_base != NULL) {
                event_base_free(ctx->ev_base);
                ctx->ev_base = NULL;
            }
        }
#endif
    }

    /* synchronous */
    if (!log_ctx->redis_setup.is_async) {
        if (ctx->sync) {
            redisReply *reply;
            int i;
            for (i = 0; i < ctx->batch_count; i++) {
                redisGetReply(ctx->sync, (void **)&reply);
                if (reply) {
                    freeReplyObject(reply);
                }
            }
            redisFree(ctx->sync);
            ctx->sync = NULL;
        }
        ctx->tried = 0;
        ctx->batch_count = 0;
    }

    if (ctx != NULL) {
        SCFree(ctx);
    }
}

#endif //#ifdef HAVE_LIBHIREDIS
