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
 * \author Mike Pomraning <mpomraning@qualys.com>
 */

#ifndef SURICATA_UTIL_LOGOPENFILE_H
#define SURICATA_UTIL_LOGOPENFILE_H

#include "threads.h"
#include "conf.h"            /* ConfNode   */
#include "util-buffer.h"
#include "util-hash.h"

#ifdef HAVE_LIBHIREDIS
#include "util-log-redis.h"
#endif /* HAVE_LIBHIREDIS */

#include "output-eve.h"

enum LogFileType {
    LOGFILE_TYPE_FILE,
    LOGFILE_TYPE_UNIX_DGRAM,
    LOGFILE_TYPE_UNIX_STREAM,
    LOGFILE_TYPE_REDIS,
    /** New style or modular filetypes. */
    LOGFILE_TYPE_FILETYPE,
    LOGFILE_TYPE_NOTSET
};

typedef struct ThreadLogFileHashEntry {
    struct LogFileCtx_ *ctx;

    uint64_t thread_id;          /* OS thread identifier */
    ThreadId internal_thread_id; /* Suri internal thread id; to assist output plugins correlating
                                    usage */
    uint16_t slot_number;        /* Slot identifier - used when forming per-thread output names*/
    bool isopen;
} ThreadLogFileHashEntry;

struct LogFileCtx_;
typedef struct LogThreadedFileCtx_ {
    SCMutex mutex;
    HashTable *ht;
    char *append;
} LogThreadedFileCtx;

typedef struct LogFileTypeCtx_ {
    SCEveFileType *filetype;
    void *init_data;
    void *thread_data;
} LogFileTypeCtx;

/** Global structure for Output Context */
typedef struct LogFileCtx_ {
    union {
        FILE *fp;
#ifdef HAVE_LIBHIREDIS
        void *redis;
#endif
    };
    LogThreadedFileCtx *threads;

    union {
#ifdef HAVE_LIBHIREDIS
        RedisSetup redis_setup;
#endif
    };

    int (*Write)(const char *buffer, int buffer_len, struct LogFileCtx_ *fp);
    void (*Close)(struct LogFileCtx_ *fp);
    void (*Flush)(struct LogFileCtx_ *fp);

    LogFileTypeCtx filetype;

    /** It will be locked if the log/alert
     * record cannot be written to the file in one call */
    SCMutex fp_mutex;

    /** When threaded, track of the parent and thread id */
    bool threaded;
    struct LogFileCtx_ *parent;
    ThreadLogFileHashEntry *entry;

    /** the type of file */
    enum LogFileType type;

    /** The name of the file */
    char *filename;

    /** File permissions */
    uint32_t filemode;

    /** File buffering */
    uint32_t buffer_size;

    /** Suricata sensor name */
    char *sensor_name;

    /** Handle auto-connecting / reconnecting sockets */
    int is_sock;
    int sock_type;
    uint64_t reconn_timer;

    /** The next time to rotate log file, if rotate interval is
        specified. */
    time_t rotate_time;

    /** The interval to rotate the log file */
    uint64_t rotate_interval;

    /**< Used by some alert loggers like the unified ones that append
     * the date onto the end of files. */
    char *prefix;
    uint32_t prefix_len;

    /** Generic size_limit and size_current
     * They must be common to the threads accessing the same file */
    uint64_t size_limit;    /**< file size limit */
    uint64_t size_current;  /**< file current size */

    /* flag to avoid multiple threads printing the same stats */
    uint8_t flags;

    /* flags to set when sending over a socket */
    uint8_t send_flags;

    /* Flag if file is a regular file or not.  Only regular files
     * allow for rotation. */
    uint8_t is_regular;

    /* JSON flags */
    size_t json_flags;  /* passed to json_dump_callback() */

    /* Flag set when file rotation notification is received. */
    int rotation_flag;

    /* if set to true EVE will add a pcap file record */
    bool is_pcap_offline;

    /* Socket types may need to drop events to keep from blocking
     * Suricata. */
    uint64_t dropped;

    uint64_t output_errors;

    /* Track buffered content */
    uint64_t bytes_since_last_flush;
} LogFileCtx;

/* Min time (msecs) before trying to reconnect a Unix domain socket */
#define LOGFILE_RECONN_MIN_TIME     500

/* flags for LogFileCtx */
#define LOGFILE_ROTATE_INTERVAL 0x04

/* Default EVE output buffering size */
#define LOGFILE_EVE_BUFFER_SIZE (8 * 1024)

LogFileCtx *LogFileNewCtx(void);
int LogFileFreeCtx(LogFileCtx *);
int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer);
void LogFileFlush(LogFileCtx *file_ctx);

LogFileCtx *LogFileEnsureExists(ThreadId thread_id, LogFileCtx *lf_ctx);
int SCConfLogOpenGeneric(ConfNode *conf, LogFileCtx *, const char *, int);
int SCConfLogReopen(LogFileCtx *);
bool SCLogOpenThreadedFile(const char *log_path, const char *append, LogFileCtx *parent_ctx);

#endif /* SURICATA_UTIL_LOGOPENFILE_H */
