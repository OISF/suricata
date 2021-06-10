/* Copyright (C) 2014 Open Information Security Foundation
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

#ifndef __UTIL_LUA_H__
#define __UTIL_LUA_H__

#ifndef HAVE_LUA

/* If we don't have Lua, create a typedef for lua_State so the
 * exported Lua functions don't fail the build. */
typedef void lua_State;

#else

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-luajit.h"

typedef struct LuaStreamingBuffer_ {
    const uint8_t *data;
    uint32_t data_len;
    uint8_t flags;
} LuaStreamingBuffer;

lua_State *LuaGetState(void);
void LuaReturnState(lua_State *s);

/* gets */

/** \brief get tv pointer from the lua state */
ThreadVars *LuaStateGetThreadVars(lua_State *luastate);

Packet *LuaStateGetPacket(lua_State *luastate);
void *LuaStateGetTX(lua_State *luastate);

/** \brief get flow pointer from lua state
 *
 *  \retval f flow poiner or NULL if it was not set
 */
Flow *LuaStateGetFlow(lua_State *luastate);

PacketAlert *LuaStateGetPacketAlert(lua_State *luastate);

Signature *LuaStateGetSignature(lua_State *luastate);

/** \brief get file pointer from the lua state */
File *LuaStateGetFile(lua_State *luastate);

LuaStreamingBuffer *LuaStateGetStreamingBuffer(lua_State *luastate);

int LuaStateGetDirection(lua_State *luastate);

/* sets */

void LuaStateSetPacket(lua_State *luastate, Packet *p);
void LuaStateSetTX(lua_State *luastate, void *tx, const uint64_t tx_id);

/** \brief set a flow pointer in the lua state
 *
 *  \param f flow pointer
 */
void LuaStateSetFlow(lua_State *luastate, Flow *f);

void LuaStateSetPacketAlert(lua_State *luastate, PacketAlert *pa);

void LuaStateSetSignature(lua_State *luastate, const Signature *s);

void LuaStateSetFile(lua_State *luastate, File *file);

void LuaStateSetThreadVars(lua_State *luastate, ThreadVars *tv);

void LuaStateSetStreamingBuffer(lua_State *luastate, LuaStreamingBuffer *b);

void LuaStateSetDirection(lua_State *luastate, int direction);

void LuaPrintStack(lua_State *state);

int LuaPushStringBuffer(lua_State *luastate, const uint8_t *input, size_t input_len);

int LuaPushInteger(lua_State *luastate, lua_Integer n);

#endif /* HAVE_LUA */

#endif /* __UTIL_LUA_H__ */
