/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifdef HAVE_LUA

typedef struct DetectLuaThreadData {
    lua_State *luastate;
    uint32_t flags;
    int alproto;
} DetectLuaThreadData;

#define DETECT_LUAJIT_MAX_FLOWVARS  15
#define DETECT_LUAJIT_MAX_FLOWINTS  15

typedef struct DetectLuaData {
    int thread_ctx_id;
    int negated;
    char *filename;
    uint32_t flags;
    AppProto alproto;
    char *buffername; /* buffer name in case of a single buffer */
    uint32_t flowint[DETECT_LUAJIT_MAX_FLOWINTS];
    uint16_t flowints;
    uint16_t flowvars;
    uint32_t flowvar[DETECT_LUAJIT_MAX_FLOWVARS];
    uint32_t sid;
    uint32_t rev;
    uint32_t gid;
} DetectLuaData;

#endif /* HAVE_LUA */

/* prototypes */
void DetectLuaRegister (void);
int DetectLuaMatchBuffer(DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        uint8_t *buffer, uint32_t buffer_len, uint32_t offset,
        Flow *f);

void DetectLuaPostSetup(Signature *s);

#endif /* __DETECT_FILELUAJIT_H__ */
