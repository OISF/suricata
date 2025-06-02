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

#ifndef SURICATA_DETECT_LUA_H
#define SURICATA_DETECT_LUA_H

#include "util-lua.h"
#include "util-lua-sandbox.h"

typedef struct DetectLuaThreadData {
    lua_State *luastate;
    uint32_t flags;
} DetectLuaThreadData;

#define DETECT_LUA_MAX_FLOWVARS 15
#define DETECT_LUA_MAX_FLOWINTS 15
#define DETECT_LUA_MAX_BYTEVARS 15

typedef struct DetectLuaDataBytevarEntry_ {
    char *name;
    uint32_t id;
} DetectLuaDataBytevarEntry;

typedef struct DetectLuaData {
    int thread_ctx_id;
    int negated;
    char *filename;
    uint32_t flags;
    char *buffername; /* buffer name in case of a single buffer */
    uint32_t flowint[DETECT_LUA_MAX_FLOWINTS];
    uint16_t flowints;
    uint16_t flowvars;
    uint32_t flowvar[DETECT_LUA_MAX_FLOWVARS];
    uint16_t bytevars;
    DetectLuaDataBytevarEntry bytevar[DETECT_LUA_MAX_BYTEVARS];
    uint64_t alloc_limit;
    uint64_t instruction_limit;
    int allow_restricted_functions;
} DetectLuaData;

/* prototypes */
void DetectLuaRegister (void);
int DetectLuaMatchBuffer(DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        const uint8_t *buffer, uint32_t buffer_len, uint32_t offset,
        Flow *f);

void LuaDumpStack(lua_State *state, const char *prefix);

#endif /* SURICATA_DETECT_LUA_H */
