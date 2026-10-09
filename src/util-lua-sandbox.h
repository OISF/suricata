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
    uint64_t alloc_limit_cfg;
    uint64_t alloc_baseline;
    bool alloc_baseline_done;
    /* gross bytes allocated while the current call is open (between the
     * Reset and the Update): the engine's setup pushes are not script
     * memory; the gross count keeps a GC step during the setup from
     * undercounting them via the previous call's reclaims */
    uint64_t alloc_since_start;
    /* lifetime gross bytes allocated; never decremented */
    uint64_t alloc_bytes_allocated;

    /* Execution Limits */
    uint64_t instruction_count;
    uint64_t instruction_limit;
    // used by lua_sethook
    int hook_instruction_count;

    /* Errors. */
    bool blocked_function_error;
    bool instruction_count_error;
    bool memory_limit_error;

    /* invocation generation: bumped once per script invocation
     * (LuaStateSetThreadVars); the dnp3 points cursor compares it to
     * know its cached pointers are inside the invocation that set them */
    uint64_t invocation_gen;
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

/* alloc_limit (max-bytes) handling. The cap is the configured limit on
 * top of the state's setup-time baseline (loaded libs, the script chunk
 * and whatever thread_init() stored), captured once on first use, plus
 * the call's own inputs (the inspected buffer and args table, pushed
 * between the Reset and the Update). Per-call working memory and values
 * the script retains between calls both count against the configured
 * limit, while the baseline and the call's own inputs do not. To give
 * the setup code the freedom to push buffers without failing the cap, the
 * limit is temporarily disabled while the per-call data is prepared and
 * then restored.
 *
 * ```
 *     // get configured limit and reset active limit to 0
 *     const uint64_t cfg_limit = SCLuaSbResetBytesLimit(tlua->luastate);
 *     // push some data to the state
 *     LuaPushStringBuffer(tlua->luastate, input, (size_t)input_len);
 *     // restore the limit
 *     SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
 *     // fix the cap at baseline + configured limit; the data pushed
 *     // between the Reset and the Update (the call's own inputs) stays exempt
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
 * Fixes the cap at baseline + configured limit; the Reset->Update delta
 * (the call's own inputs) stays exempt.
 */
void SCLuaSbUpdateBytesLimit(lua_State *L);

/*
 * Set the bytes limit. Meant to be used with the value returned from
 * `SCLuaSbResetBytesLimit`
 */
void SCLuaSbRestoreBytesLimit(lua_State *L, const uint64_t cfg_limit);

#endif /*  SURICATA_UTIL_LUA_SANDBOX_H */
