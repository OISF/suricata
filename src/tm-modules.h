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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __TM_MODULES_H__
#define __TM_MODULES_H__

#include "tm-threads-common.h"
#include "threadvars.h"

/* thread flags */
#define TM_FLAG_RECEIVE_TM      0x01
#define TM_FLAG_DECODE_TM       0x02
#define TM_FLAG_STREAM_TM       0x04
#define TM_FLAG_DETECT_TM       0x08
#define TM_FLAG_LOGAPI_TM       0x10 /**< TM is run by Log API */
#define TM_FLAG_MANAGEMENT_TM   0x20
#define TM_FLAG_COMMAND_TM      0x40

typedef TmEcode (*ThreadInitFunc)(ThreadVars *, const void *, void **);
typedef TmEcode (*ThreadDeinitFunc)(ThreadVars *, void *);
typedef void (*ThreadExitPrintStatsFunc)(ThreadVars *, void *);

typedef struct TmModule_ {
    const char *name;

    /** thread handling */
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);

    /** the packet processing function */
    TmEcode (*Func)(ThreadVars *, Packet *, void *);

    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);

    /** terminates the capture loop in PktAcqLoop */
    TmEcode (*PktAcqBreakLoop)(ThreadVars *, void *);

    TmEcode (*Management)(ThreadVars *, void *);

    /** global Init/DeInit */
    TmEcode (*Init)(void);
    TmEcode (*DeInit)(void);
#ifdef UNITTESTS
    void (*RegisterTests)(void);
#endif
    uint8_t cap_flags; /**< Flags to indicate the capability requirement of
                           the given TmModule */
    /* Other flags used by the module */
    uint8_t flags;
} TmModule;

extern TmModule tmm_modules[TMM_SIZE];

/**
 * Structure that output modules use to maintain private data.
 */
typedef struct OutputCtx_ {

    /** Pointer to data private to the output. */
    void *data;

    /** Pointer to a cleanup function. */
    void (*DeInit)(struct OutputCtx_ *);

    TAILQ_HEAD(, OutputModule_) submodules;
} OutputCtx;

TmModule *TmModuleGetByName(const char *name);
TmModule *TmModuleGetById(int id);
int TmModuleGetIdByName(const char *name);
int TmModuleGetIDForTM(TmModule *tm);
TmEcode TmModuleRegister(char *name, int (*module_func)(ThreadVars *, Packet *, void *));
void TmModuleDebugList(void);
void TmModuleRegisterTests(void);
#ifdef PROFILING
const char * TmModuleTmmIdToString(TmmId id);
#endif
void TmModuleRunInit(void);
void TmModuleRunDeInit(void);

#endif /* __TM_MODULES_H__ */

