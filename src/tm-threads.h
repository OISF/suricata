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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

#include "tm-modules.h"

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_MAX,
};

extern ThreadVars *tv_root[TVT_MAX];

extern SCMutex tv_root_lock;

void Tm1SlotSetFunc(ThreadVars *, TmModule *, void *);
void TmVarSlotSetFuncAppend(ThreadVars *, TmModule *, void *);
ThreadVars *TmThreadCreate(char *, char *, char *, char *, char *, char *,
                           void *(fn_p)(void *), int);
ThreadVars *TmThreadCreatePacketHandler(char *, char *, char *, char *, char *,
                                        char *);
ThreadVars *TmThreadCreateMgmtThread(char *name, void *(fn_p)(void *), int);
TmEcode TmThreadSpawn(ThreadVars *);
void TmThreadSetFlags(ThreadVars *, uint8_t);
void TmThreadSetAOF(ThreadVars *, uint8_t);
void TmThreadKillThread(ThreadVars *);
void TmThreadKillThreads(void);
void TmThreadAppend(ThreadVars *, int);
void TmThreadRemove(ThreadVars *, int);

TmEcode TmThreadSetCPUAffinity(ThreadVars *, uint16_t);
TmEcode TmThreadSetThreadPriority(ThreadVars *, int);
TmEcode TmThreadSetupOptions(ThreadVars *);
void TmThreadSetPrio(ThreadVars *);

void TmThreadInitMC(ThreadVars *);
void TmThreadTestThreadUnPaused(ThreadVars *);
void TmThreadContinue(ThreadVars *);
void TmThreadContinueThreads(void);
void TmThreadPause(ThreadVars *);
void TmThreadPauseThreads(void);
void TmThreadCheckThreadState(void);
TmEcode TmThreadWaitOnThreadInit(void);
ThreadVars *TmThreadsGetCallingThread(void);

int TmThreadsCheckFlag(ThreadVars *, uint8_t);
void TmThreadsSetFlag(ThreadVars *, uint8_t);
void TmThreadsUnsetFlag(ThreadVars *, uint8_t);


#endif /* __TM_THREADS_H__ */

