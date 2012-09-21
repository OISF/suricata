/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#ifndef __DETECT_LUAJIT_H__
#define __DETECT_LUAJIT_H__

#ifdef HAVE_LUAJIT

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

typedef struct DetectLuajitThreadData {
    lua_State *luastate;
    uint32_t flags;
    int alproto;
} DetectLuajitThreadData;

typedef struct DetectLuajitData {
    int thread_ctx_id;
    int negated;
    char *filename;
    uint32_t flags;
    int alproto;
    char *buffername; /* buffer name in case of a single buffer */
} DetectLuajitData;
#endif

/* prototypes */
void DetectLuajitRegister (void);
int DetectLuajitMatchBuffer(DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm, uint8_t *buffer, uint32_t buffer_len, uint32_t offset);

int DetectLuajitSetupStatesPool(int num, int reloads);

#endif /* __DETECT_FILELUAJIT_H__ */
