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
 * \author Mike Pomraning <mpomraning@qualys.com>
 *
 * File-like output for logging:  regular files and sockets.
 */

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "util-logopenfile.h"
#include "suricata.h"
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */
#include "util-byte.h"
#include "util-conf.h"
#include "util-path.h"
#include "util-misc.h"
#include "util-time.h"

#if defined(HAVE_SYS_UN_H) && defined(HAVE_SYS_SOCKET_H) && defined(HAVE_SYS_TYPES_H)
#define BUILD_WITH_UNIXSOCKET
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif

#ifdef HAVE_LIBHIREDIS
#include "util-log-redis.h"
#endif /* HAVE_LIBHIREDIS */

#define LOGFILE_NAME_MAX 255

static bool LogFileNewThreadedCtx(LogFileCtx *parent_ctx, const char *log_path, const char *append,
        ThreadLogFileHashEntry *entry);

// Threaded eve.json identifier
static SC_ATOMIC_DECL_AND_INIT_WITH_VAL(uint16_t, eve_file_id, 1);

#ifdef BUILD_WITH_UNIXSOCKET
/** \brief connect to the indicated local stream socket, logging any errors
 *  \param path filesystem path to connect to
 *  \param log_err, non-zero if connect failure should be logged.
 *  \retval FILE* on success (fdopen'd wrapper of underlying socket)
 *  \retval NULL on error
 */
static FILE *
SCLogOpenUnixSocketFp(const char *path, int sock_type, int log_err)
{
    struct sockaddr_un saun;
    int s = -1;
    FILE * ret = NULL;

    memset(&saun, 0x00, sizeof(saun));

    s = socket(PF_UNIX, sock_type, 0);
    if (s < 0) goto err;

    saun.sun_family = AF_UNIX;
    strlcpy(saun.sun_path, path, sizeof(saun.sun_path));

    if (connect(s, (const struct sockaddr *)&saun, sizeof(saun)) < 0)
        goto err;

    ret = fdopen(s, "w");
    if (ret == NULL)
        goto err;

    return ret;

err:
    if (log_err)
        SCLogWarning(
                "Error connecting to socket \"%s\": %s (will keep trying)", path, strerror(errno));

    if (s >= 0)
        close(s);

    return NULL;
}

/**
 * \brief Attempt to reconnect a disconnected (or never-connected) Unix domain socket.
 * \retval 1 if it is now connected; otherwise 0
 */
static int SCLogUnixSocketReconnect(LogFileCtx *log_ctx)
{
    int disconnected = 0;
    if (log_ctx->fp) {
        SCLogWarning("Write error on Unix socket \"%s\": %s; reconnecting...", log_ctx->filename,
                strerror(errno));
        fclose(log_ctx->fp);
        log_ctx->fp = NULL;
        log_ctx->reconn_timer = 0;
        disconnected = 1;
    }

    struct timeval tv;
    uint64_t now;
    gettimeofday(&tv, NULL);
    now = (uint64_t)tv.tv_sec * 1000;
    now += tv.tv_usec / 1000;           /* msec resolution */
    if (log_ctx->reconn_timer != 0 &&
            (now - log_ctx->reconn_timer) < LOGFILE_RECONN_MIN_TIME) {
        /* Don't bother to try reconnecting too often. */
        return 0;
    }
    log_ctx->reconn_timer = now;

    log_ctx->fp = SCLogOpenUnixSocketFp(log_ctx->filename, log_ctx->sock_type, 0);
    if (log_ctx->fp) {
        /* Connected at last (or reconnected) */
        SCLogDebug("Reconnected socket \"%s\"", log_ctx->filename);
    } else if (disconnected) {
        SCLogWarning("Reconnect failed: %s (will keep trying)", strerror(errno));
    }

    return log_ctx->fp ? 1 : 0;
}

static int SCLogFileWriteSocket(const char *buffer, int buffer_len,
        LogFileCtx *ctx)
{
    int tries = 0;
    int ret = 0;
    bool reopen = false;
    if (ctx->fp == NULL && ctx->is_sock) {
        SCLogUnixSocketReconnect(ctx);
    }
tryagain:
    ret = -1;
    reopen = 0;
    errno = 0;
    if (ctx->fp != NULL) {
        int fd = fileno(ctx->fp);
        ssize_t size = send(fd, buffer, buffer_len, ctx->send_flags);
        if (size > -1) {
            ret = 0;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                SCLogDebug("Socket would block, dropping event.");
            } else if (errno == EINTR) {
                if (tries++ == 0) {
                    SCLogDebug("Interrupted system call, trying again.");
                    goto tryagain;
                }
                SCLogDebug("Too many interrupted system calls, "
                        "dropping event.");
            } else {
                /* Some other error. Assume badness and reopen. */
                SCLogDebug("Send failed: %s", strerror(errno));
                reopen = true;
            }
        }
    }

    if (reopen && tries++ == 0) {
        if (SCLogUnixSocketReconnect(ctx)) {
            goto tryagain;
        }
    }

    if (ret == -1) {
        ctx->dropped++;
    }

    return ret;
}
#endif /* BUILD_WITH_UNIXSOCKET */
static inline void OutputWriteLock(pthread_mutex_t *m)
{
    SCMutexLock(m);

}

/**
 * \brief Flush a log file.
 */
static void SCLogFileFlushNoLock(LogFileCtx *log_ctx)
{
    log_ctx->bytes_since_last_flush = 0;
    SCFflushUnlocked(log_ctx->fp);
}

static void SCLogFileFlush(LogFileCtx *log_ctx)
{
    OutputWriteLock(&log_ctx->fp_mutex);
    SCLogFileFlushNoLock(log_ctx);
    SCMutexUnlock(&log_ctx->fp_mutex);
}

/**
 * \brief Write buffer to log file.
 * \retval 0 on failure; otherwise, the return value of fwrite_unlocked (number of
 * characters successfully written).
 */
static int SCLogFileWriteNoLock(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    int ret = 0;

    DEBUG_VALIDATE_BUG_ON(log_ctx->is_sock);

    /* Check for rotation. */
    if (log_ctx->rotation_flag) {
        log_ctx->rotation_flag = 0;
        SCConfLogReopen(log_ctx);
    }

    if (log_ctx->flags & LOGFILE_ROTATE_INTERVAL) {
        time_t now = time(NULL);
        if (now >= log_ctx->rotate_time) {
            SCConfLogReopen(log_ctx);
            log_ctx->rotate_time = now + log_ctx->rotate_interval;
        }
    }

    if (log_ctx->fp) {
        SCClearErrUnlocked(log_ctx->fp);
        if (1 != SCFwriteUnlocked(buffer, buffer_len, 1, log_ctx->fp)) {
            /* Only the first error is logged */
            if (!log_ctx->output_errors) {
                SCLogError("%s error while writing to %s",
                        SCFerrorUnlocked(log_ctx->fp) ? strerror(errno) : "unknown error",
                        log_ctx->filename);
            }
            log_ctx->output_errors++;
            return ret;
        }

        log_ctx->bytes_since_last_flush += buffer_len;

        if (log_ctx->buffer_size && log_ctx->bytes_since_last_flush >= log_ctx->buffer_size) {
            SCLogDebug("%s: flushing %" PRIu64 " during write", log_ctx->filename,
                    log_ctx->bytes_since_last_flush);
            SCLogFileFlushNoLock(log_ctx);
        }
    }

    return ret;
}

/**
 * \brief Write buffer to log file.
 * \retval 0 on failure; otherwise, the return value of fwrite (number of
 * characters successfully written).
 */
static int SCLogFileWrite(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    OutputWriteLock(&log_ctx->fp_mutex);
    int ret = 0;

#ifdef BUILD_WITH_UNIXSOCKET
    if (log_ctx->is_sock) {
        ret = SCLogFileWriteSocket(buffer, buffer_len, log_ctx);
    } else
#endif
    {
        ret = SCLogFileWriteNoLock(buffer, buffer_len, log_ctx);
    }

    SCMutexUnlock(&log_ctx->fp_mutex);

    return ret;
}

/** \brief generate filename based on pattern
 *  \param pattern pattern to use
 *  \retval char* on success
 *  \retval NULL on error
 */
static char *SCLogFilenameFromPattern(const char *pattern)
{
    char *filename = SCMalloc(PATH_MAX);
    if (filename == NULL) {
        return NULL;
    }

    int rc = SCTimeToStringPattern(time(NULL), pattern, filename, PATH_MAX);
    if (rc != 0) {
        SCFree(filename);
        return NULL;
    }

    return filename;
}

static void SCLogFileCloseNoLock(LogFileCtx *log_ctx)
{
    SCLogDebug("Closing %s", log_ctx->filename);
    if (log_ctx->fp) {
        if (log_ctx->buffer_size)
            SCFflushUnlocked(log_ctx->fp);
        fclose(log_ctx->fp);
    }

    if (log_ctx->output_errors) {
        SCLogError("There were %" PRIu64 " output errors to %s", log_ctx->output_errors,
                log_ctx->filename);
    }
}

static void SCLogFileClose(LogFileCtx *log_ctx)
{
    SCMutexLock(&log_ctx->fp_mutex);
    SCLogFileCloseNoLock(log_ctx);
    SCMutexUnlock(&log_ctx->fp_mutex);
}

static char ThreadLogFileHashCompareFunc(
        void *data1, uint16_t datalen1, void *data2, uint16_t datalen2)
{
    ThreadLogFileHashEntry *p1 = (ThreadLogFileHashEntry *)data1;
    ThreadLogFileHashEntry *p2 = (ThreadLogFileHashEntry *)data2;

    if (p1 == NULL || p2 == NULL)
        return 0;

    return p1->thread_id == p2->thread_id;
}
static uint32_t ThreadLogFileHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    const ThreadLogFileHashEntry *ent = (ThreadLogFileHashEntry *)data;

    return ent->thread_id % ht->array_size;
}

static void ThreadLogFileHashFreeFunc(void *data)
{
    BUG_ON(data == NULL);
    ThreadLogFileHashEntry *thread_ent = (ThreadLogFileHashEntry *)data;

    if (!thread_ent)
        return;

    if (thread_ent->isopen) {
        LogFileCtx *lf_ctx = thread_ent->ctx;
        /* Free the leaf log file entries */
        if (!lf_ctx->threaded) {
            LogFileFreeCtx(lf_ctx);
        }
    }
    SCFree(thread_ent);
}

bool SCLogOpenThreadedFile(const char *log_path, const char *append, LogFileCtx *parent_ctx)
{
        parent_ctx->threads = SCCalloc(1, sizeof(LogThreadedFileCtx));
        if (!parent_ctx->threads) {
            SCLogError("Unable to allocate threads container");
            return false;
        }

        parent_ctx->threads->ht = HashTableInit(255, ThreadLogFileHashFunc,
                ThreadLogFileHashCompareFunc, ThreadLogFileHashFreeFunc);
        if (!parent_ctx->threads->ht) {
            FatalError("Unable to initialize thread/entry hash table");
        }

        parent_ctx->threads->append = SCStrdup(append == NULL ? DEFAULT_LOG_MODE_APPEND : append);
        if (!parent_ctx->threads->append) {
            SCLogError("Unable to allocate threads append setting");
            goto error_exit;
        }

        SCMutexInit(&parent_ctx->threads->mutex, NULL);
        return true;

error_exit:

        if (parent_ctx->threads->append) {
            SCFree(parent_ctx->threads->append);
        }
        if (parent_ctx->threads->ht) {
            HashTableFree(parent_ctx->threads->ht);
        }
        SCFree(parent_ctx->threads);
        parent_ctx->threads = NULL;
        return false;
}

/** \brief open the indicated file, logging any errors
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \param mode permissions to set on file
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static FILE *SCLogOpenFileFp(
        const char *path, const char *append_setting, uint32_t mode, const uint32_t buffer_size)
{
    FILE *ret = NULL;

    char *filename = SCLogFilenameFromPattern(path);
    if (filename == NULL) {
        return NULL;
    }

    int rc = SCCreateDirectoryTree(filename, false);
    if (rc < 0) {
        SCFree(filename);
        return NULL;
    }

    if (SCConfValIsTrue(append_setting)) {
        ret = fopen(filename, "a");
    } else {
        ret = fopen(filename, "w");
    }

    if (ret == NULL) {
        SCLogError("Error opening file: \"%s\": %s", filename, strerror(errno));
        goto error_exit;
    } else {
        if (mode != 0) {
#ifdef OS_WIN32
            int r = _chmod(filename, (mode_t)mode);
#else
            int r = fchmod(fileno(ret), (mode_t)mode);
#endif
            if (r < 0) {
                SCLogWarning("Could not chmod %s to %o: %s", filename, mode, strerror(errno));
            }
        }
    }

    /* Set buffering behavior */
    if (buffer_size == 0) {
        setbuf(ret, NULL);
        SCLogConfig("Setting output to %s non-buffered", filename);
    } else {
        if (setvbuf(ret, NULL, _IOFBF, buffer_size) < 0)
            FatalError("unable to set %s to buffered: %d", filename, buffer_size);
        SCLogConfig("Setting output to %s buffered [limit %d bytes]", filename, buffer_size);
    }

error_exit:
    SCFree(filename);

    return ret;
}

/** \brief open a generic output "log file", which may be a regular file or a socket
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \param default_filename Default name of file to open, if not specified in ConfNode
 *  \param rotate Register the file for rotation in HUP.
 *  \retval 0 on success
 *  \retval -1 on error
 */
int SCConfLogOpenGeneric(
        SCConfNode *conf, LogFileCtx *log_ctx, const char *default_filename, int rotate)
{
    char log_path[PATH_MAX];
    const char *log_dir;
    const char *filename, *filetype;

    // Arg check
    if (conf == NULL || log_ctx == NULL || default_filename == NULL) {
        SCLogError("SCConfLogOpenGeneric(conf %p, ctx %p, default %p) "
                   "missing an argument",
                conf, log_ctx, default_filename);
        return -1;
    }
    if (log_ctx->fp != NULL) {
        SCLogError("SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = SCConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = default_filename;

    log_dir = SCConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }

    /* Rotate log file based on time */
    const char *rotate_int = SCConfNodeLookupChildValue(conf, "rotate-interval");
    if (rotate_int != NULL) {
        time_t now = time(NULL);
        log_ctx->flags |= LOGFILE_ROTATE_INTERVAL;

        /* Use a specific time */
        if (strcmp(rotate_int, "minute") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 60;
        } else if (strcmp(rotate_int, "hour") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 3600;
        } else if (strcmp(rotate_int, "day") == 0) {
            log_ctx->rotate_time = now + SCGetSecondsUntil(rotate_int, now);
            log_ctx->rotate_interval = 86400;
        }

        /* Use a timer */
        else {
            log_ctx->rotate_interval = SCParseTimeSizeString(rotate_int);
            if (log_ctx->rotate_interval == 0) {
                FatalError("invalid rotate-interval value");
            }
            log_ctx->rotate_time = now + log_ctx->rotate_interval;
        }
    }

    filetype = SCConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    /* Determine the buffering for this output device; a value of 0 means to not buffer;
     * any other value must be a multiple of 4096
     * The default value is 0 (no buffering)
     */
    uint32_t buffer_size = LOGFILE_EVE_BUFFER_SIZE;
    const char *buffer_size_value = SCConfNodeLookupChildValue(conf, "buffer-size");
    if (buffer_size_value != NULL) {
        uint32_t value;
        if (ParseSizeStringU32(buffer_size_value, &value) < 0) {
            FatalError("Error parsing "
                       "buffer-size - %s. Killing engine",
                    buffer_size_value);
        }
        buffer_size = value;
    }

    SCLogDebug("buffering: %s -> %d", buffer_size_value, buffer_size);
    const char *filemode = SCConfNodeLookupChildValue(conf, "filemode");
    uint32_t mode = 0;
    if (filemode != NULL && StringParseUint32(&mode, 8, (uint16_t)strlen(filemode), filemode) > 0) {
        log_ctx->filemode = mode;
    }

    const char *append = SCConfNodeLookupChildValue(conf, "append");
    if (append == NULL)
        append = DEFAULT_LOG_MODE_APPEND;

    /* JSON flags */
    log_ctx->json_flags = JSON_PRESERVE_ORDER|JSON_COMPACT|
                          JSON_ENSURE_ASCII|JSON_ESCAPE_SLASH;

    SCConfNode *json_flags = SCConfNodeLookupChild(conf, "json");

    if (json_flags != 0) {
        const char *preserve_order = SCConfNodeLookupChildValue(json_flags, "preserve-order");
        if (preserve_order != NULL && SCConfValIsFalse(preserve_order))
            log_ctx->json_flags &= ~(JSON_PRESERVE_ORDER);

        const char *compact = SCConfNodeLookupChildValue(json_flags, "compact");
        if (compact != NULL && SCConfValIsFalse(compact))
            log_ctx->json_flags &= ~(JSON_COMPACT);

        const char *ensure_ascii = SCConfNodeLookupChildValue(json_flags, "ensure-ascii");
        if (ensure_ascii != NULL && SCConfValIsFalse(ensure_ascii))
            log_ctx->json_flags &= ~(JSON_ENSURE_ASCII);

        const char *escape_slash = SCConfNodeLookupChildValue(json_flags, "escape-slash");
        if (escape_slash != NULL && SCConfValIsFalse(escape_slash))
            log_ctx->json_flags &= ~(JSON_ESCAPE_SLASH);
    }

#ifdef BUILD_WITH_UNIXSOCKET
    if (log_ctx->threaded) {
        if (strcasecmp(filetype, "unix_stream") == 0 || strcasecmp(filetype, "unix_dgram") == 0) {
            FatalError("Socket file types do not support threaded output");
        }
    }
#endif
    if (!(strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0 || strcasecmp(filetype, "file") == 0)) {
        SCLogConfig("buffering setting ignored for %s output types", filetype);
    }

    // Now, what have we been asked to open?
    if (strcasecmp(filetype, "unix_stream") == 0) {
#ifdef BUILD_WITH_UNIXSOCKET
        /* Don't bail. May be able to connect later. */
        log_ctx->is_sock = 1;
        log_ctx->sock_type = SOCK_STREAM;
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_STREAM, 1);
#else
        return -1;
#endif
    } else if (strcasecmp(filetype, "unix_dgram") == 0) {
#ifdef BUILD_WITH_UNIXSOCKET
        /* Don't bail. May be able to connect later. */
        log_ctx->is_sock = 1;
        log_ctx->sock_type = SOCK_DGRAM;
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_DGRAM, 1);
#else
        return -1;
#endif
    } else if (strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0 ||
               strcasecmp(filetype, "file") == 0) {
        log_ctx->is_regular = 1;
        log_ctx->buffer_size = buffer_size;
        if (!log_ctx->threaded) {
            log_ctx->fp =
                    SCLogOpenFileFp(log_path, append, log_ctx->filemode, log_ctx->buffer_size);
            if (log_ctx->fp == NULL)
                return -1; // Error already logged by Open...Fp routine
        } else {
            if (!SCLogOpenThreadedFile(log_path, append, log_ctx)) {
                return -1;
            }
        }
        if (rotate) {
            OutputRegisterFileRotationFlag(&log_ctx->rotation_flag);
        }
    } else {
        SCLogError("Invalid entry for "
                   "%s.filetype.  Expected \"regular\" (default), \"unix_stream\", "
                   "or \"unix_dgram\"",
                conf->name);
    }
    log_ctx->filename = SCStrdup(log_path);
    if (unlikely(log_ctx->filename == NULL)) {
        SCLogError("Failed to allocate memory for filename");
        return -1;
    }

#ifdef BUILD_WITH_UNIXSOCKET
    /* If a socket and running live, do non-blocking writes. */
    if (log_ctx->is_sock && !IsRunModeOffline(SCRunmodeGet())) {
        SCLogInfo("Setting logging socket of non-blocking in live mode.");
        log_ctx->send_flags |= MSG_DONTWAIT;
    }
#endif
    SCLogInfo("%s output device (%s) initialized: %s", conf->name, filetype,
              filename);

    return 0;
}

/**
 * \brief Reopen a regular log file with the side-affect of truncating it.
 *
 * This is useful to clear the log file and start a new one, or to
 * re-open the file after its been moved by something external
 * (eg. logrotate).
 */
int SCConfLogReopen(LogFileCtx *log_ctx)
{
    if (!log_ctx->is_regular) {
        /* Not supported and not needed on non-regular files. */
        return 0;
    }

    if (log_ctx->filename == NULL) {
        SCLogWarning("Can't re-open LogFileCtx without a filename.");
        return -1;
    }

    if (log_ctx->fp != NULL) {
        fclose(log_ctx->fp);
    }

    /* Reopen the file. Append is forced in case the file was not
     * moved as part of a rotation process. */
    SCLogDebug("Reopening log file %s.", log_ctx->filename);
    log_ctx->fp =
            SCLogOpenFileFp(log_ctx->filename, "yes", log_ctx->filemode, log_ctx->buffer_size);
    if (log_ctx->fp == NULL) {
        return -1; // Already logged by Open..Fp routine.
    }

    return 0;
}

/** \brief LogFileNewCtx() Get a new LogFileCtx
 *  \retval LogFileCtx * pointer if successful, NULL if error
 *  */
LogFileCtx *LogFileNewCtx(void)
{
    LogFileCtx* lf_ctx;
    lf_ctx = (LogFileCtx*)SCCalloc(1, sizeof(LogFileCtx));

    if (lf_ctx == NULL)
        return NULL;

    lf_ctx->Write = SCLogFileWrite;
    lf_ctx->Close = SCLogFileClose;
    lf_ctx->Flush = SCLogFileFlush;

    return lf_ctx;
}

/** \brief LogFileThread2Slot() Return a file entry
 * \retval ThreadLogFileHashEntry * file entry for caller
 *
 * This function returns the file entry for the calling thread.
 * Each thread -- identified by its operating system thread-id -- has its
 * own file entry that includes a file pointer.
 */
static ThreadLogFileHashEntry *LogFileThread2Slot(LogThreadedFileCtx *parent, ThreadId thread_id)
{
    ThreadLogFileHashEntry thread_hash_entry;

    /* Check hash table for thread id*/
    thread_hash_entry.thread_id = SCGetThreadIdLong();
    ThreadLogFileHashEntry *ent =
            HashTableLookup(parent->ht, &thread_hash_entry, sizeof(thread_hash_entry));

    if (!ent) {
        ent = SCCalloc(1, sizeof(*ent));
        if (!ent) {
            FatalError("Unable to allocate thread/hash-entry entry");
        }
        ent->thread_id = thread_hash_entry.thread_id;
        ent->internal_thread_id = thread_id;
        SCLogDebug(
                "Trying to add thread %" PRIi64 " to entry %d", ent->thread_id, ent->slot_number);
        if (0 != HashTableAdd(parent->ht, ent, 0)) {
            FatalError("Unable to add thread/hash-entry mapping");
        }
    }
    return ent;
}

/** \brief LogFileEnsureExists() Ensure a log file context for the thread exists
 * \param parent_ctx
 * \retval LogFileCtx * pointer if successful; NULL otherwise
 */
LogFileCtx *LogFileEnsureExists(ThreadId thread_id, LogFileCtx *parent_ctx)
{
    /* threaded output disabled */
    if (!parent_ctx->threaded)
        return parent_ctx;

    LogFileCtx *ret_ctx = NULL;
    SCMutexLock(&parent_ctx->threads->mutex);
    /* Find this thread's entry */
    ThreadLogFileHashEntry *entry = LogFileThread2Slot(parent_ctx->threads, thread_id);
    SCLogDebug("%s: Adding reference for thread %" PRIi64
               " (local thread id %d) to file %s [ctx %p]",
            t_thread_name, SCGetThreadIdLong(), thread_id, parent_ctx->filename, parent_ctx);

    bool new = entry->isopen;
    /* has it been opened yet? */
    if (!new) {
        SCLogDebug("%s: Opening new file for thread/id %d to file %s [ctx %p]", t_thread_name,
                thread_id, parent_ctx->filename, parent_ctx);
        if (LogFileNewThreadedCtx(
                    parent_ctx, parent_ctx->filename, parent_ctx->threads->append, entry)) {
            entry->isopen = true;
            ret_ctx = entry->ctx;
        } else {
            SCLogDebug(
                    "Unable to open slot %d for file %s", entry->slot_number, parent_ctx->filename);
            (void)HashTableRemove(parent_ctx->threads->ht, entry, 0);
        }
    } else {
        ret_ctx = entry->ctx;
    }
    SCMutexUnlock(&parent_ctx->threads->mutex);

    if (sc_log_global_log_level >= SC_LOG_DEBUG) {
        if (new) {
            SCLogDebug("Existing file for thread/entry %p reference to file %s [ctx %p]", entry,
                    parent_ctx->filename, parent_ctx);
        }
    }

    return ret_ctx;
}

/** \brief LogFileThreadedName() Create file name for threaded EVE storage
 *
 */
static bool LogFileThreadedName(
        const char *original_name, char *threaded_name, size_t len, uint32_t unique_id)
{
    sc_errno = SC_OK;

    if (strcmp("/dev/null", original_name) == 0) {
        strlcpy(threaded_name, original_name, len);
        return true;
    }

    const char *base = SCBasename(original_name);
    if (!base) {
        FatalError("Invalid filename for threaded mode \"%s\"; "
                   "no basename found.",
                original_name);
    }

    /* Check if basename has an extension */
    char *dot = strrchr(base, '.');
    if (dot) {
        char *tname = SCStrdup(original_name);
        if (!tname) {
            sc_errno = SC_ENOMEM;
            return false;
        }

        /* Fetch extension location from original, not base
         * for update
         */
        dot = strrchr(original_name, '.');
        ptrdiff_t dotpos = dot - original_name;
        tname[dotpos] = '\0';
        char *ext = tname + dotpos + 1;
        if (strlen(tname) && strlen(ext)) {
            snprintf(threaded_name, len, "%s.%u.%s", tname, unique_id, ext);
        } else {
            FatalError("Invalid filename for threaded mode \"%s\"; "
                       "filenames must include an extension, e.g: \"name.ext\"",
                    original_name);
        }
        SCFree(tname);
    } else {
        snprintf(threaded_name, len, "%s.%u", original_name, unique_id);
    }
    return true;
}

/** \brief LogFileNewThreadedCtx() Create file context for threaded output
 * \param parent_ctx
 * \param log_path
 * \param append
 * \param entry
 */
static bool LogFileNewThreadedCtx(LogFileCtx *parent_ctx, const char *log_path, const char *append,
        ThreadLogFileHashEntry *entry)
{
    LogFileCtx *thread = SCCalloc(1, sizeof(LogFileCtx));
    if (!thread) {
        SCLogError("Unable to allocate thread file context entry %p", entry);
        return false;
    }

    *thread = *parent_ctx;
    if (parent_ctx->type == LOGFILE_TYPE_FILE) {
        char fname[LOGFILE_NAME_MAX];
        entry->slot_number = SC_ATOMIC_ADD(eve_file_id, 1);
        if (!LogFileThreadedName(log_path, fname, sizeof(fname), entry->slot_number)) {
            SCLogError("Unable to create threaded filename for log");
            goto error;
        }
        SCLogDebug("%s: thread open -- using name %s [replaces %s] - thread %d [slot %d]",
                t_thread_name, fname, log_path, entry->internal_thread_id, entry->slot_number);
        thread->fp = SCLogOpenFileFp(fname, append, thread->filemode, parent_ctx->buffer_size);
        if (thread->fp == NULL) {
            goto error;
        }
        thread->filename = SCStrdup(fname);
        if (!thread->filename) {
            SCLogError("Unable to duplicate filename for context entry %p", entry);
            goto error;
        }
        thread->is_regular = true;
        thread->Write = SCLogFileWriteNoLock;
        thread->Close = SCLogFileCloseNoLock;
        OutputRegisterFileRotationFlag(&thread->rotation_flag);
    } else if (parent_ctx->type == LOGFILE_TYPE_FILETYPE) {
        entry->slot_number = SC_ATOMIC_ADD(eve_file_id, 1);
        SCLogDebug("%s - thread %d [slot %d]", log_path, entry->internal_thread_id,
                entry->slot_number);
        thread->filetype.filetype->ThreadInit(thread->filetype.init_data, entry->internal_thread_id,
                &thread->filetype.thread_data);
    }
    thread->threaded = false;
    thread->parent = parent_ctx;
    thread->entry = entry;
    entry->ctx = thread;

    return true;

error:
    if (parent_ctx->type == LOGFILE_TYPE_FILE) {
        SC_ATOMIC_SUB(eve_file_id, 1);
        if (thread->fp) {
            thread->Close(thread);
        }
    }

    if (thread) {
        SCFree(thread);
    }
    return false;
}

/** \brief LogFileFreeCtx() Destroy a LogFileCtx (Close the file and free memory)
 *  \param lf_ctx pointer to the OutputCtx
 *  \retval int 1 if successful, 0 if error
 *  */
int LogFileFreeCtx(LogFileCtx *lf_ctx)
{
    if (lf_ctx == NULL) {
        SCReturnInt(0);
    }

    if (lf_ctx->type == LOGFILE_TYPE_FILETYPE && lf_ctx->filetype.filetype->ThreadDeinit) {
        lf_ctx->filetype.filetype->ThreadDeinit(
                lf_ctx->filetype.init_data, lf_ctx->filetype.thread_data);
    }

    if (lf_ctx->threaded) {
        BUG_ON(lf_ctx->threads == NULL);
        SCMutexDestroy(&lf_ctx->threads->mutex);
        if (lf_ctx->threads->append)
            SCFree(lf_ctx->threads->append);
        if (lf_ctx->threads->ht) {
            HashTableFree(lf_ctx->threads->ht);
        }
        SCFree(lf_ctx->threads);
    } else {
        if (lf_ctx->type != LOGFILE_TYPE_FILETYPE) {
            if (lf_ctx->fp != NULL) {
                lf_ctx->Close(lf_ctx);
            }
        }
        SCMutexDestroy(&lf_ctx->fp_mutex);
    }

    if (lf_ctx->prefix != NULL) {
        SCFree(lf_ctx->prefix);
        lf_ctx->prefix_len = 0;
    }

    if(lf_ctx->filename != NULL)
        SCFree(lf_ctx->filename);

    if (lf_ctx->sensor_name)
        SCFree(lf_ctx->sensor_name);

    if (!lf_ctx->threaded) {
        OutputUnregisterFileRotationFlag(&lf_ctx->rotation_flag);
    }

    /* Deinitialize output filetypes. We only want to call this for
     * the parent of threaded output, or always for non-threaded
     * output. */
    if (lf_ctx->type == LOGFILE_TYPE_FILETYPE && lf_ctx->parent == NULL) {
        lf_ctx->filetype.filetype->Deinit(lf_ctx->filetype.init_data);
    }

#ifdef HAVE_LIBHIREDIS
    if (lf_ctx->type == LOGFILE_TYPE_REDIS) {
        if (lf_ctx->redis_setup.stream_format != NULL) {
            SCFree(lf_ctx->redis_setup.stream_format);
        }
    }
#endif

    memset(lf_ctx, 0, sizeof(*lf_ctx));
    SCFree(lf_ctx);

    SCReturnInt(1);
}

void LogFileFlush(LogFileCtx *file_ctx)
{
    SCLogDebug("%s: bytes-to-flush %ld", file_ctx->filename, file_ctx->bytes_since_last_flush);
    file_ctx->Flush(file_ctx);
}

int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer)
{
    if (file_ctx->type == LOGFILE_TYPE_FILE || file_ctx->type == LOGFILE_TYPE_UNIX_DGRAM ||
            file_ctx->type == LOGFILE_TYPE_UNIX_STREAM) {
        /* append \n for files only */
        MemBufferWriteString(buffer, "\n");
        file_ctx->Write((const char *)MEMBUFFER_BUFFER(buffer),
                        MEMBUFFER_OFFSET(buffer), file_ctx);
    } else if (file_ctx->type == LOGFILE_TYPE_FILETYPE) {
        file_ctx->filetype.filetype->Write((const char *)MEMBUFFER_BUFFER(buffer),
                MEMBUFFER_OFFSET(buffer), file_ctx->filetype.init_data,
                file_ctx->filetype.thread_data);
    }
#ifdef HAVE_LIBHIREDIS
    else if (file_ctx->type == LOGFILE_TYPE_REDIS) {
        SCMutexLock(&file_ctx->fp_mutex);
        LogFileWriteRedis(file_ctx, (const char *)MEMBUFFER_BUFFER(buffer),
                MEMBUFFER_OFFSET(buffer));
        SCMutexUnlock(&file_ctx->fp_mutex);
    }
#endif

    return 0;
}
