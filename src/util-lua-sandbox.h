/* Copyright (C) 2014-2023 Open Information Security Foundation
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
 * \author Jo Johnson <pyrojoe314@gmail.com>
 */

#ifndef __UTIL_LUA_SANDBOX_H__
#define __UTIL_LUA_SANDBOX_H__

#ifndef HAVE_LUA
/* If we don't have Lua, create a typedef for sb_lua_State so the
 * exported Lua functions don't fail the build. */
typedef void sb_lua_state;
#else
#include <stdlib.h>
#include "lua.h"

#if !defined(SANDBOX_ALLOC_CTX)
#define SANDBOX_CTX "SANDBOX_CTX"
#endif

/*
 *  Lua sandbox usage:  The only needed changes to use the sandboxed lua state are
 *      to replace calls to lua_newstate and lua_close with sb_newstate and sb_close
 *      Additionally, sb_loadrestricted can be used to load a restricted set of packages
 *      that prevent side effecting outside of the lua runtime
 */

/*
 *  Struct to store a lua_state and the additional metadata required to sandbox it
 */
typedef struct sb_lua_state {
    lua_State *L;

    // Allocation limits
    uint64_t alloc_bytes;
    uint64_t alloc_limit;

    // Execution Limits
    uint64_t instruction_count;
    uint64_t instruction_limit;
    uint64_t hook_instruction_count;
} sb_lua_state;

enum sb_level { NONE, EXTERNAL_RESTRICTED, PERFORMANCE_RESTRICTED };

/*
 *  Replaces luaL_newstate.  Sets an upper bound for allocations and bytecode
 *      instructions for the lua runtime on this state.
 *
 *  alloclimit - maximium number of bytes lua can allocate before receiving out of memory.
 *      A value of zero will not limit allocations
 *  instructionlimit - maximum number of lua bytecode instructions before an error is thrown
 *      A value of zero will not limit the number of instructions
 */
lua_State *sb_newstate(uint64_t alloclimit, uint64_t instructionlimit);

/*
 *  Replaces lua_close.  Handles freeing the sb_lua_state
 */
void sb_close(lua_State *sb);

/*
 *  Resets the instruction counter for the sandbox to 0
 */
void sb_resetinstructioncounter(lua_State *sb);

/*
 *  Sets the maximum number of lua instructions before erroring out
 */
void sb_setinstructionlimit(lua_State *L, uint64_t instruction_limit);

/*
 *  Replaces luaL_openlibs.  Only opens allowed paackages for the sandbox and
 *  masks out dangerous functions from the base.
 */
LUALIB_API void sb_loadrestricted(lua_State *L);

#endif /* HAVE_LUA */

#endif /*  __UTIL_LUA_SANDBOX_H__ */