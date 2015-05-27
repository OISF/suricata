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

typedef struct TmModule_ {
    char *name;

    /** thread handling */
    TmEcode (*ThreadInit)(ThreadVars *, void *, void **);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);

    /** the packet processing function */
    TmEcode (*Func)(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);

    TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);

    TmEcode (*Management)(ThreadVars *, void *);

    /** global Init/DeInit */
    TmEcode (*Init)(void);
    TmEcode (*DeInit)(void);

    void (*RegisterTests)(void);

    uint8_t cap_flags;   /**< Flags to indicate the capability requierment of
                             the given TmModule */
    /* Other flags used by the module */
    uint8_t flags;
    /* priority in the logging order, higher priority is runned first */
    uint8_t priority;
} TmModule;

TmModule tmm_modules[TMM_SIZE];

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
const char * TmModuleTmmIdToString(TmmId id);

void TmModuleRunInit(void);
void TmModuleRunDeInit(void);

#endif /* __TM_MODULES_H__ */

