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
    size_t alloc_bytes;
    uint64_t alloc_limit;

    /* Execution Limits */
    uint64_t instruction_count;
    uint64_t instruction_limit;
    // used by lua_sethook
    int hook_instruction_count;

    /* Errors. */
    bool blocked_function_error;
    bool instruction_count_error;
    bool memory_limit_error;
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

/* alloc_limit (max-bytes) handling. To give the script the full budget
 * during it's execution, temporary disable the limit and then restore
 * it with the existing use as baseline
 *
 * ```
 *     // get configured limit and reset active limit to 0
 *     const uint64_t cfg_limit = SCLuaSbResetBytesLimit(tlua->luastate);
 *     // push some data to the state
 *     LuaPushStringBuffer(tlua->luastate, input, (size_t)input_len);
 *     // restore the limit, which may now be lower than `alloc_bytes`.
 *     SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
 *     // update allowance to take `alloc_bytes` as the baseline, so
 *     // effectively: sb->alloc_bytes + sb->alloc_limit
 *     SCLuaSbUpdateBytesLimit(tlua->luastate);
 *
 *     ... run script, lua_pcall...
 *
 *     while (lua_gettop(tlua->luastate) > 0) {
 *         lua_pop(tlua->luastate, 1);
 *     }
 *     // restore the original alloc_limit
 *     SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
 * ```
 */

/*
 * Resets the byte limit and returns the existing limit.
 * Meant to be used to temporarily disable the limit during preparation
 * time for a script to run. */
uint64_t SCLuaSbResetBytesLimit(lua_State *L);

/*
 * Update the alloc_limit to take the pre-script initialization bytes
 * as the base line.
 */
void SCLuaSbUpdateBytesLimit(lua_State *L);

/*
 * Set the bytes limit. Meant to be used with the value returned from
 * `SCLuaSbResetBytesLimit`
 */
void SCLuaSbRestoreBytesLimit(lua_State *L, const uint64_t cfg_limit);

#endif /*  SURICATA_UTIL_LUA_SANDBOX_H */
