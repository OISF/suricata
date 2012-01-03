/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __TM_MODULES_H__
#define __TM_MODULES_H__

#include "tm-threads-common.h"
#include "threadvars.h"

/* thread flags */
#define TM_FLAG_RECEIVE_TM      0x01

typedef struct TmModule_ {
    char *name;

    /** thread handling */
    TmEcode (*ThreadInit)(ThreadVars *, void *, void **);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);

    /** the packet processing function */
    TmEcode (*Func)(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);

    /** global Init/DeInit */
    TmEcode (*Init)(void);
    TmEcode (*DeInit)(void);

    void (*RegisterTests)(void);

    uint8_t cap_flags;   /**< Flags to indicate the capability requierment of
                             the given TmModule */
    /* Other flags used by the module */
    uint8_t flags;
} TmModule;

TmModule tmm_modules[TMM_SIZE];

/** Global structure for Output Context */
typedef struct LogFileCtx_ {
    FILE *fp;
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
} LogFileCtx;

/* flags for LogFileCtx */
#define LOGFILE_HEADER_WRITTEN 0x01
#define LOGFILE_ALERTS_PRINTED 0x02

/**
 * Structure that output modules use to maintain private data.
 */
typedef struct OutputCtx_ {

    /** Pointer to data private to the output. */
    void *data;

    /** Pointer to a cleanup function. */
    void (*DeInit)(struct OutputCtx_ *);
} OutputCtx;

LogFileCtx *LogFileNewCtx();
int LogFileFreeCtx(LogFileCtx *);

TmModule *TmModuleGetByName(char *name);
TmModule *TmModuleGetById(int id);
int TmModuleGetIDForTM(TmModule *tm);
TmEcode TmModuleRegister(char *name, int (*module_func)(ThreadVars *, Packet *, void *));
void TmModuleDebugList(void);
void TmModuleRegisterTests(void);
const char * TmModuleTmmIdToString(TmmId id);

void TmModuleRunInit(void);
void TmModuleRunDeInit(void);

#endif /* __TM_MODULES_H__ */

