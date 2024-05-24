/* Copyright (C) 2023-2024 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_LUA_SANDBOX_H
#define SURICATA_UTIL_LUA_SANDBOX_H

#include "lua.h"
#include "suricata-common.h"

/*
 *  Lua sandbox usage:  The only needed changes to use the sandboxed lua state are
 *      to replace calls to lua_newstate and lua_close with SCLuaSbStateNew and SCLuaSbStateClose
 *      Additionally, SCLuaSbLoadRestricted can be used to load a restricted set of packages
 *      that prevent side effecting outside of the lua runtime
 */

/*
 *  Struct to store a lua_state and the additional metadata required to sandbox it
 */
typedef struct SCLuaSbState {
    lua_State *L;

    /* Allocation limits */
    uint64_t alloc_bytes;
    uint64_t alloc_limit;

    /* Execution Limits */
    uint64_t instruction_count;
    uint64_t instruction_limit;
    uint64_t hook_instruction_count;

    /* Errors. */
    bool blocked_function_error;
    bool instruction_count_error;
} SCLuaSbState;

/*
 *  Replaces luaL_newstate.  Sets an upper bound for allocations and bytecode
 *      instructions for the lua runtime on this state.
 *
 *  alloclimit - maximium number of bytes lua can allocate before receiving out of memory.
 *      A value of zero will not limit allocations
 *  instructionlimit - maximum number of lua bytecode instructions before an error is thrown
 *      A value of zero will not limit the number of instructions
 */
lua_State *SCLuaSbStateNew(uint64_t alloclimit, uint64_t instructionlimit);

/*
 *  Replaces lua_close.  Handles freeing the SCLuaSbState
 */
void SCLuaSbStateClose(lua_State *sb);

/**
 * Retreive the SCLuaSbState from a lua_State.
 */
SCLuaSbState *SCLuaSbGetContext(lua_State *L);

/*
 *  Resets the instruction counter for the sandbox to 0
 */
void SCLuaSbResetInstructionCounter(lua_State *sb);

/*
 *  Replaces luaL_openlibs.  Only opens allowed packages for the sandbox and
 *  masks out dangerous functions from the base.
 */
void SCLuaSbLoadLibs(lua_State *L);

#endif /*  SURICATA_UTIL_LUA_SANDBOX_H */
