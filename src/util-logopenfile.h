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

typedef struct {
    uint16_t fileno;
} PcieFile;

/** Global structure for Output Context */
typedef struct LogFileCtx_ {
    union {
        FILE *fp;
        PcieFile *pcie_fp;
    };

    int (*Write)(const char *buffer, int buffer_len, struct LogFileCtx_ *fp);
    void (*Close)(struct LogFileCtx_ *fp);

    /** It will be locked if the log/alert
     * record cannot be written to the file in one call */
    SCMutex fp_mutex;

    /** The name of the file */
    char *filename;

    /**< Used by some alert loggers like the unified ones that append
     * the date onto the end of files. */
    char *prefix;

    /** Generic size_limit and size_current
     * They must be common to the threads accesing the same file */
    uint64_t size_limit;    /**< file size limit */
    uint64_t size_current;  /**< file current size */

    /* Alerts on the module (not on the file) */
    uint64_t alerts;
    /* flag to avoid multiple threads printing the same stats */
    uint8_t flags;

    /* Flag if file is a regular file or not.  Only regular files
     * allow for rotataion. */
    uint8_t is_regular;

    /* Flag set when file rotation notification is received. */
    int rotation_flag;
} LogFileCtx;

/* flags for LogFileCtx */
#define LOGFILE_HEADER_WRITTEN 0x01
#define LOGFILE_ALERTS_PRINTED 0x02

LogFileCtx *LogFileNewCtx(void);
int LogFileFreeCtx(LogFileCtx *);

int SCConfLogOpenGeneric(ConfNode *conf, LogFileCtx *, const char *);
int SCConfLogReopen(LogFileCtx *);

#endif /* __UTIL_LOGOPENFILE_H__ */
