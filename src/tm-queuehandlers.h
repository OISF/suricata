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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __TM_QUEUEHANDLERS_H__
#define __TM_QUEUEHANDLERS_H__

enum {
    TMQH_NOT_SET,
    TMQH_SIMPLE,
    TMQH_PACKETPOOL,
    TMQH_FLOW,

    TMQH_SIZE,
};

typedef struct Tmqh_ {
    const char *name;
    Packet *(*InHandler)(ThreadVars *);
    void (*InShutdownHandler)(ThreadVars *);
    void (*OutHandler)(ThreadVars *, Packet *);
    void *(*OutHandlerCtxSetup)(const char *);
    void (*OutHandlerCtxFree)(void *);
    void (*RegisterTests)(void);
} Tmqh;

extern Tmqh tmqh_table[TMQH_SIZE];

void TmqhSetup (void);
void TmqhCleanup(void);
int TmqhNameToID(const char *name);
Tmqh *TmqhGetQueueHandlerByName(const char *name);
Tmqh *TmqhGetQueueHandlerByID(const int id);

#endif /* __TM_QUEUEHANDLERS_H__ */

