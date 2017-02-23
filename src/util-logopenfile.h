/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __UTIL_LOGOPENFILE_H__
#define __UTIL_LOGOPENFILE_H__

#include "conf.h"            /* ConfNode   */
#include "tm-modules.h"      /* LogFileCtx */
#include "util-buffer.h"

#ifdef HAVE_LIBHIREDIS
#include "util-log-redis.h"
#endif /* HAVE_LIBHIREDIS */


typedef struct {
    uint16_t fileno;
} PcieFile;

enum LogFileType { LOGFILE_TYPE_FILE,
                   LOGFILE_TYPE_SYSLOG,
                   LOGFILE_TYPE_UNIX_DGRAM,
                   LOGFILE_TYPE_UNIX_STREAM,
                   LOGFILE_TYPE_REDIS };

typedef struct SyslogSetup_ {
    int alert_syslog_level;
} SyslogSetup;


/** Global structure for Output Context */
typedef struct LogFileCtx_ {
    union {
        FILE *fp;
        PcieFile *pcie_fp;
#ifdef HAVE_LIBHIREDIS
        void *redis;
#endif
    };

    union {
        SyslogSetup syslog_setup;
#ifdef HAVE_LIBHIREDIS
        RedisSetup redis_setup;
#endif
    };

    int (*Write)(const char *buffer, int buffer_len, struct LogFileCtx_ *fp);
    void (*Close)(struct LogFileCtx_ *fp);

    /** It will be locked if the log/alert
     * record cannot be written to the file in one call */
    SCMutex fp_mutex;

    /** the type of file */
    enum LogFileType type;

    /** The name of the file */
    char *filename;

    /** File permissions */
    uint32_t filemode;

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
    size_t prefix_len;

    /** Generic size_limit and size_current
     * They must be common to the threads accesing the same file */
    uint64_t size_limit;    /**< file size limit */
    uint64_t size_current;  /**< file current size */

    /* flag to avoid multiple threads printing the same stats */
    uint8_t flags;

    /* flags to set when sending over a socket */
    uint8_t send_flags;

    /* Flag if file is a regular file or not.  Only regular files
     * allow for rotataion. */
    uint8_t is_regular;

    /* JSON flags */
    size_t json_flags;  /* passed to json_dump_callback() */

    /* Flag set when file rotation notification is received. */
    int rotation_flag;

    /* Set to true if the filename should not be timestamped. */
    bool nostamp;

    /* Socket types may need to drop events to keep from blocking
     * Suricata. */
    uint64_t dropped;
} LogFileCtx;

/* Min time (msecs) before trying to reconnect a Unix domain socket */
#define LOGFILE_RECONN_MIN_TIME     500

/* flags for LogFileCtx */
#define LOGFILE_HEADER_WRITTEN  0x01
#define LOGFILE_ALERTS_PRINTED  0x02
#define LOGFILE_ROTATE_INTERVAL 0x04

LogFileCtx *LogFileNewCtx(void);
int LogFileFreeCtx(LogFileCtx *);
int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer);

int SCConfLogOpenGeneric(ConfNode *conf, LogFileCtx *, const char *, int);
int SCConfLogReopen(LogFileCtx *);

#endif /* __UTIL_LOGOPENFILE_H__ */
