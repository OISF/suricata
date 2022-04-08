/* vi: set et ts=4: */
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
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */
#include "util-byte.h"
#include "util-logopenfile.h"

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

static bool LogFileNewThreadedCtx(LogFileCtx *parent_ctx, const char *log_path, const char *append, int i);

// Threaded eve.json identifier
static SC_ATOMIC_DECL_AND_INIT_WITH_VAL(uint32_t, eve_file_id, 1);

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
        SCLogWarning(SC_ERR_SOCKET,
            "Error connecting to socket \"%s\": %s (will keep trying)",
            path, strerror(errno));

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
        SCLogWarning(SC_ERR_SOCKET,
            "Write error on Unix socket \"%s\": %s; reconnecting...",
            log_ctx->filename, strerror(errno));
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
        SCLogNotice("Reconnected socket \"%s\"", log_ctx->filename);
    } else if (disconnected) {
        SCLogWarning(SC_ERR_SOCKET, "Reconnect failed: %s (will keep trying)",
            strerror(errno));
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
 * \brief Write buffer to log file.
 * \retval 0 on failure; otherwise, the return value of fwrite_unlocked (number of
 * characters successfully written).
 */
static int SCLogFileWriteNoLock(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    int ret = 0;

    BUG_ON(log_ctx->is_sock);

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
                SCLogError(SC_ERR_LOG_OUTPUT, "%s error while writing to %s",
                        SCFerrorUnlocked(log_ctx->fp) ? strerror(errno) : "unknown error",
                        log_ctx->filename);
            }
            log_ctx->output_errors++;
        } else {
            SCFflushUnlocked(log_ctx->fp);
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
            clearerr(log_ctx->fp);
            if (1 != fwrite(buffer, buffer_len, 1, log_ctx->fp)) {
                /* Only the first error is logged */
                if (!log_ctx->output_errors) {
                    SCLogError(SC_ERR_LOG_OUTPUT, "%s error while writing to %s",
                            ferror(log_ctx->fp) ? strerror(errno) : "unknown error",
                            log_ctx->filename);
                }
                log_ctx->output_errors++;
            } else {
                fflush(log_ctx->fp);
            }
        }
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
    if (log_ctx->fp)
        fclose(log_ctx->fp);

    if (log_ctx->output_errors) {
        SCLogError(SC_ERR_LOG_OUTPUT, "There were %" PRIu64 " output errors to %s",
                log_ctx->output_errors, log_ctx->filename);
    }
}

static void SCLogFileClose(LogFileCtx *log_ctx)
{
    SCMutexLock(&log_ctx->fp_mutex);
    SCLogFileCloseNoLock(log_ctx);
    SCMutexUnlock(&log_ctx->fp_mutex);
}

static char ThreadSlotHashCompareFunc(
        void *data1, uint16_t datalen1, void *data2, uint16_t datalen2)
{
    ThreadSlotHashEntry *p1 = (ThreadSlotHashEntry *)data1;
    ThreadSlotHashEntry *p2 = (ThreadSlotHashEntry *)data2;

    if (p1 == NULL || p2 == NULL)
        return 0;

    return p1->thread_id == p2->thread_id;
}
static uint32_t ThreadSlotHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    const ThreadSlotHashEntry *ent = (ThreadSlotHashEntry *)data;

    return ent->thread_id % ht->array_size;
}

static void ThreadSlotHashFreeFunc(void *data)
{
    ThreadSlotHashEntry *thread_ent = (ThreadSlotHashEntry *)data;

    if (thread_ent) {
        SCFree(thread_ent);
    }
}

bool SCLogOpenThreadedFile(
        const char *log_path, const char *append, LogFileCtx *parent_ctx, int slot_count)
{
        parent_ctx->threads = SCCalloc(1, sizeof(LogThreadedFileCtx));
        if (!parent_ctx->threads) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate threads container");
            return false;
        }

        parent_ctx->threads->ht = HashTableInit(
                255, ThreadSlotHashFunc, ThreadSlotHashCompareFunc, ThreadSlotHashFreeFunc);
        if (!parent_ctx->threads->ht) {
            FatalError(SC_ERR_HASH_TABLE_INIT, "Unable to initialize thread/slot table");
        }

        parent_ctx->threads->append = SCStrdup(append == NULL ? DEFAULT_LOG_MODE_APPEND : append);
        if (!parent_ctx->threads->append) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate threads append setting");
            goto error_exit;
        }

        parent_ctx->threads->slot_count = slot_count;
        parent_ctx->threads->last_slot = 0;
        parent_ctx->threads->lf_slots = SCCalloc(slot_count, sizeof(LogFileCtx *));
        if (!parent_ctx->threads->lf_slots) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate thread slots");
            goto error_exit;
        }
        SCLogDebug("Allocated %d file context pointers for threaded array",
                    parent_ctx->threads->slot_count);
        for (int slot = 1; slot < parent_ctx->threads->slot_count; slot++) {
            if (!LogFileNewThreadedCtx(parent_ctx, log_path, parent_ctx->threads->append, slot)) {
                /* TODO: clear allocated entries [1, slot) */
                goto error_exit;
            }
        }
        SCMutexInit(&parent_ctx->threads->mutex, NULL);
        return true;

error_exit:

        if (parent_ctx->threads->lf_slots) {
            SCFree(parent_ctx->threads->lf_slots);
        }
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
static FILE *
SCLogOpenFileFp(const char *path, const char *append_setting, uint32_t mode)
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

    if (ConfValIsTrue(append_setting)) {
        ret = fopen(filename, "a");
    } else {
        ret = fopen(filename, "w");
    }

    if (ret == NULL) {
        SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                   filename, strerror(errno));
    } else {
        if (mode != 0) {
#ifdef OS_WIN32
            int r = _chmod(filename, (mode_t)mode);
#else
            int r = fchmod(fileno(ret), (mode_t)mode);
#endif
            if (r < 0) {
                SCLogWarning(SC_WARN_CHMOD, "Could not chmod %s to %o: %s",
                             filename, mode, strerror(errno));
            }
        }
    }

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
int
SCConfLogOpenGeneric(ConfNode *conf,
                     LogFileCtx *log_ctx,
                     const char *default_filename,
                     int rotate)
{
    char log_path[PATH_MAX];
    const char *log_dir;
    const char *filename, *filetype;

    // Arg check
    if (conf == NULL || log_ctx == NULL || default_filename == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric(conf %p, ctx %p, default %p) "
                   "missing an argument",
                   conf, log_ctx, default_filename);
        return -1;
    }
    if (log_ctx->fp != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = default_filename;

    log_dir = ConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }

    /* Rotate log file based on time */
    const char *rotate_int = ConfNodeLookupChildValue(conf, "rotate-interval");
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
                           FatalError(SC_ERR_FATAL,
                                      "invalid rotate-interval value");
            }
            log_ctx->rotate_time = now + log_ctx->rotate_interval;
        }
    }

    filetype = ConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    const char *filemode = ConfNodeLookupChildValue(conf, "filemode");
    uint32_t mode = 0;
    if (filemode != NULL && StringParseUint32(&mode, 8, (uint16_t)strlen(filemode), filemode) > 0) {
        log_ctx->filemode = mode;
    }

    const char *append = ConfNodeLookupChildValue(conf, "append");
    if (append == NULL)
        append = DEFAULT_LOG_MODE_APPEND;

    /* JSON flags */
    log_ctx->json_flags = JSON_PRESERVE_ORDER|JSON_COMPACT|
                          JSON_ENSURE_ASCII|JSON_ESCAPE_SLASH;

    ConfNode *json_flags = ConfNodeLookupChild(conf, "json");

    if (json_flags != 0) {
        const char *preserve_order = ConfNodeLookupChildValue(json_flags,
                                                              "preserve-order");
        if (preserve_order != NULL && ConfValIsFalse(preserve_order))
            log_ctx->json_flags &= ~(JSON_PRESERVE_ORDER);

        const char *compact = ConfNodeLookupChildValue(json_flags, "compact");
        if (compact != NULL && ConfValIsFalse(compact))
            log_ctx->json_flags &= ~(JSON_COMPACT);

        const char *ensure_ascii = ConfNodeLookupChildValue(json_flags,
                                                            "ensure-ascii");
        if (ensure_ascii != NULL && ConfValIsFalse(ensure_ascii))
            log_ctx->json_flags &= ~(JSON_ENSURE_ASCII);

        const char *escape_slash = ConfNodeLookupChildValue(json_flags,
                                                            "escape-slash");
        if (escape_slash != NULL && ConfValIsFalse(escape_slash))
            log_ctx->json_flags &= ~(JSON_ESCAPE_SLASH);
    }

#ifdef BUILD_WITH_UNIXSOCKET
    if (log_ctx->threaded) {
        if (strcasecmp(filetype, "unix_stream") == 0 || strcasecmp(filetype, "unix_dgram") == 0) {
            FatalError(SC_ERR_FATAL, "Socket file types do not support threaded output");
        }
    }
#endif
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
        if (!log_ctx->threaded) {
            log_ctx->fp = SCLogOpenFileFp(log_path, append, log_ctx->filemode);
            if (log_ctx->fp == NULL)
                return -1; // Error already logged by Open...Fp routine
        } else {
            if (!SCLogOpenThreadedFile(log_path, append, log_ctx, 1)) {
                return -1;
            }
        }
        if (rotate) {
            OutputRegisterFileRotationFlag(&log_ctx->rotation_flag);
        }
    } else {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                   "%s.filetype.  Expected \"regular\" (default), \"unix_stream\", "
                   "or \"unix_dgram\"",
                   conf->name);
    }
    log_ctx->filename = SCStrdup(log_path);
    if (unlikely(log_ctx->filename == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate memory for filename");
        return -1;
    }

#ifdef BUILD_WITH_UNIXSOCKET
    /* If a socket and running live, do non-blocking writes. */
    if (log_ctx->is_sock && !IsRunModeOffline(RunmodeGetCurrent())) {
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
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
            "Can't re-open LogFileCtx without a filename.");
        return -1;
    }

    if (log_ctx->fp != NULL) {
        fclose(log_ctx->fp);
    }

    /* Reopen the file. Append is forced in case the file was not
     * moved as part of a rotation process. */
    SCLogDebug("Reopening log file %s.", log_ctx->filename);
    log_ctx->fp = SCLogOpenFileFp(log_ctx->filename, "yes", log_ctx->filemode);
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

    return lf_ctx;
}

/** \brief LogFileThread2Slot() Return a file slot
 * \retval int file slot for caller
 *
 * This function returns the file slot for the calling thread.
 * Each thread -- identified by its operating system thread-id -- has its
 * own slot that includes a file pointer.
 */
static int LogFileThread2Slot(LogThreadedFileCtx *parent)
{
    ThreadSlotHashEntry thread_hash_entry;

    /* Check hash table for thread id*/
    thread_hash_entry.thread_id = SCGetThreadIdLong();
    ThreadSlotHashEntry *ent =
            HashTableLookup(parent->ht, &thread_hash_entry, sizeof(thread_hash_entry));

    if (ent) {
        return ent->slot;
    }

    ent = SCCalloc(1, sizeof(*ent));
    if (!ent) {
        FatalError(SC_ERR_HASH_ADD, "Unable to allocate thread/slot entry");
    }
    ent->thread_id = thread_hash_entry.thread_id;
    ent->slot = ++parent->last_slot;
    SCLogDebug("Trying to add thread %ld to slot %d", ent->thread_id, ent->slot);
    if (0 != HashTableAdd(parent->ht, ent, 0)) {
        FatalError(SC_ERR_HASH_ADD, "Unable to add thread/slot mapping");
    }
    return ent->slot;
}

/** \brief LogFileEnsureExists() Ensure a log file context for the thread exists
 * \param parent_ctx
 * \retval LogFileCtx * pointer if successful; NULL otherwise
 */
LogFileCtx *LogFileEnsureExists(LogFileCtx *parent_ctx)
{
    /* threaded output disabled */
    if (!parent_ctx->threaded)
        return parent_ctx;

    SCMutexLock(&parent_ctx->threads->mutex);
    /* Find this thread's slot */
    int slot = LogFileThread2Slot(parent_ctx->threads);
    SCLogDebug("Adding reference for thread %ld [slot %d] to file %s [ctx %p]", SCGetThreadIdLong(),
            slot, parent_ctx->filename, parent_ctx);

    /* Add slots if necessary */
    if (slot >= parent_ctx->threads->slot_count) {
        /* ensure there's a slot for the caller */
        int new_size = MAX(parent_ctx->threads->slot_count << 1, slot + 1);
        SCLogDebug("Increasing slot count; current %d, trying %d", parent_ctx->threads->slot_count,
                new_size);
        LogFileCtx **new_array =
                SCRealloc(parent_ctx->threads->lf_slots, new_size * sizeof(LogFileCtx *));
        if (new_array == NULL) {
            /* Try one more time */
            SCLogDebug("Unable to increase file context array size to %d; trying %d", new_size,
                    slot + 1);
            new_size = slot + 1;
            new_array = SCRealloc(parent_ctx->threads->lf_slots, new_size * sizeof(LogFileCtx *));
        }

        if (new_array == NULL) {
            SCMutexUnlock(&parent_ctx->threads->mutex);
            SCLogError(
                    SC_ERR_MEM_ALLOC, "Unable to increase file context array size to %d", new_size);
            return NULL;
        }

        parent_ctx->threads->lf_slots = new_array;
        /* initialize newly added slots */
        for (int i = parent_ctx->threads->slot_count; i < new_size; i++) {
            parent_ctx->threads->lf_slots[i] = NULL;
        }
        parent_ctx->threads->slot_count = new_size;
    }

    /* has it been opened yet? */
    if (!parent_ctx->threads->lf_slots[slot]) {
        SCLogDebug("Opening new file for thread/slot %d to file %s [ctx %p]", slot,
                parent_ctx->filename, parent_ctx);
        if (!LogFileNewThreadedCtx(
                    parent_ctx, parent_ctx->filename, parent_ctx->threads->append, slot))
            BUG_ON(parent_ctx->threads->lf_slots[slot] != NULL);
    }
    SCMutexUnlock(&parent_ctx->threads->mutex);

    if (sc_log_global_log_level >= SC_LOG_DEBUG) {
        if (parent_ctx->threads->lf_slots[slot])
            SCLogDebug("Existing file for thread/slot %d reference to file %s [ctx %p]", slot,
                    parent_ctx->filename, parent_ctx);
    }

    return parent_ctx->threads->lf_slots[slot];
}

/** \brief LogFileThreadedName() Create file name for threaded EVE storage
 *
 */
static bool LogFileThreadedName(
        const char *original_name, char *threaded_name, size_t len, uint32_t unique_id)
{
    if (strcmp("/dev/null", original_name) == 0) {
        strlcpy(threaded_name, original_name, len);
        return true;
    }

    const char *base = SCBasename(original_name);
    if (!base) {
        FatalError(SC_ERR_FATAL,
                "Invalid filename for threaded mode \"%s\"; "
                "no basename found.",
                original_name);
    }

    /* Check if basename has an extension */
    char *dot = strrchr(base, '.');
    if (dot) {
        char *tname = SCStrdup(original_name);
        if (!tname) {
            return false;
        }

        /* Fetch extension location from original, not base
         * for update
         */
        dot = strrchr(original_name, '.');
        int dotpos = dot - original_name;
        tname[dotpos] = '\0';
        char *ext = tname + dotpos + 1;
        if (strlen(tname) && strlen(ext)) {
            snprintf(threaded_name, len, "%s.%u.%s", tname, unique_id, ext);
        } else {
            FatalError(SC_ERR_FATAL,
                    "Invalid filename for threaded mode \"%s\"; "
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
 * \param slot
 */
static bool LogFileNewThreadedCtx(
        LogFileCtx *parent_ctx, const char *log_path, const char *append, int slot)
{
    LogFileCtx *thread = SCCalloc(1, sizeof(LogFileCtx));
    if (!thread) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate thread file context slot %d", slot);
        return false;
    }

    *thread = *parent_ctx;
    if (parent_ctx->type == LOGFILE_TYPE_FILE) {
        char fname[LOGFILE_NAME_MAX];
        if (!LogFileThreadedName(log_path, fname, sizeof(fname), SC_ATOMIC_ADD(eve_file_id, 1))) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to create threaded filename for log");
            goto error;
        }
        SCLogDebug("Thread open -- using name %s [replaces %s]", fname, log_path);
        thread->fp = SCLogOpenFileFp(fname, append, thread->filemode);
        if (thread->fp == NULL) {
            goto error;
        }
        thread->filename = SCStrdup(fname);
        if (!thread->filename) {
            SCLogError(SC_ERR_MEM_ALLOC, "Unable to duplicate filename for context slot %d", slot);
            goto error;
        }
        thread->is_regular = true;
        thread->Write = SCLogFileWriteNoLock;
        thread->Close = SCLogFileCloseNoLock;
        OutputRegisterFileRotationFlag(&thread->rotation_flag);
    } else if (parent_ctx->type == LOGFILE_TYPE_PLUGIN) {
        thread->plugin.plugin->ThreadInit(
                thread->plugin.init_data, slot, &thread->plugin.thread_data);
    }
    thread->threaded = false;
    thread->parent = parent_ctx;
    thread->slot = slot;

    parent_ctx->threads->lf_slots[slot] = thread;
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
    parent_ctx->threads->lf_slots[slot] = NULL;
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

    if (lf_ctx->threaded) {
        BUG_ON(lf_ctx->threads == NULL);
        SCMutexDestroy(&lf_ctx->threads->mutex);
        for(int i = 0; i < lf_ctx->threads->slot_count; i++) {
            if (!lf_ctx->threads->lf_slots[i]) {
                continue;
            }
            LogFileCtx *this_ctx = lf_ctx->threads->lf_slots[i];

            if (lf_ctx->type != LOGFILE_TYPE_PLUGIN) {
                OutputUnregisterFileRotationFlag(&this_ctx->rotation_flag);
                this_ctx->Close(this_ctx);
            } else {
                lf_ctx->plugin.plugin->ThreadDeinit(
                        this_ctx->plugin.init_data, this_ctx->plugin.thread_data);
            }
            SCFree(lf_ctx->threads->lf_slots[i]->filename);
            SCFree(lf_ctx->threads->lf_slots[i]);
        }
        SCFree(lf_ctx->threads->lf_slots);
        if (lf_ctx->threads->append)
            SCFree(lf_ctx->threads->append);
        if (lf_ctx->threads->ht) {
            HashTableFree(lf_ctx->threads->ht);
        }
        SCFree(lf_ctx->threads);
    } else {
        if (lf_ctx->type != LOGFILE_TYPE_PLUGIN) {
            if (lf_ctx->fp != NULL) {
                lf_ctx->Close(lf_ctx);
            }
            if (lf_ctx->parent) {
                SCMutexLock(&lf_ctx->parent->threads->mutex);
                lf_ctx->parent->threads->lf_slots[lf_ctx->slot] = NULL;
                SCMutexUnlock(&lf_ctx->parent->threads->mutex);
            }
        }
        SCMutexDestroy(&lf_ctx->fp_mutex);
    }

    if (lf_ctx->type == LOGFILE_TYPE_PLUGIN) {
        lf_ctx->plugin.plugin->Deinit(lf_ctx->plugin.init_data);
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

    memset(lf_ctx, 0, sizeof(*lf_ctx));
    SCFree(lf_ctx);

    SCReturnInt(1);
}

int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer)
{
    if (file_ctx->type == LOGFILE_TYPE_FILE || file_ctx->type == LOGFILE_TYPE_UNIX_DGRAM ||
            file_ctx->type == LOGFILE_TYPE_UNIX_STREAM) {
        /* append \n for files only */
        MemBufferWriteString(buffer, "\n");
        file_ctx->Write((const char *)MEMBUFFER_BUFFER(buffer),
                        MEMBUFFER_OFFSET(buffer), file_ctx);
    } else if (file_ctx->type == LOGFILE_TYPE_PLUGIN) {
        file_ctx->plugin.plugin->Write((const char *)MEMBUFFER_BUFFER(buffer),
                MEMBUFFER_OFFSET(buffer), file_ctx->plugin.init_data, file_ctx->plugin.thread_data);
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
