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

#include "suricata-common.h"

#ifdef HAVE_LUA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lua.h"

#include "lauxlib.h"
#include "lualib.h"

#include "util-lua-sandbox.h"

typedef struct sb_block_function {
    const char *module;
    const char *name;
} sb_block_function;

static void sb_hook(lua_State *L, lua_Debug *ar);
static int luaopen_sandbox(lua_State *L);

static void *sb_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    (void)ud;
    (void)osize; /* not used */
    SCLuaSbState *ctx = (SCLuaSbState *)ud;
    if (nsize == 0) {
        if (ptr != NULL) {
            // ASSERT: alloc_bytes > osize
            ctx->alloc_bytes -= osize;
        }
        SCFree(ptr);
        return NULL;
    } else {
        // We can be a bit sloppy on the alloc limit since it's not supposed to be hit.
        //  ASSERT: ctx->alloc_bytes + nsize > ctx->alloc_bytes
        if (ctx->alloc_bytes + nsize > ctx->alloc_limit) {
            // TODO: Trace in a better way
            return NULL;
        }
        void *nptr = SCRealloc(ptr, nsize);
        if (nptr != NULL) {
            ctx->alloc_bytes += nsize;
        }
        return nptr;
    }
}

/*
** These are the set of libs allowed in the restricted lua sandbox
*/

static const luaL_Reg sb_restrictedlibs[] = {
    // clang-format off
    { LUA_GNAME, luaopen_base },
    { LUA_TABLIBNAME, luaopen_table },
    { LUA_STRLIBNAME, luaopen_string },
    { LUA_MATHLIBNAME, luaopen_math },
    { LUA_UTF8LIBNAME, luaopen_utf8 },

    /* TODO: Review these libs... */
#if 0
    {LUA_LOADLIBNAME, luaopen_package},
    {LUA_COLIBNAME, luaopen_coroutine},
    {LUA_IOLIBNAME, luaopen_io},
    {LUA_OSLIBNAME, luaopen_os},
#endif

    /* What is this for? */
#if 0
    { LUA_DBLIBNAME, luaopen_sandbox }, // TODO: remove this from restricted
#endif

    { NULL, NULL }
    // clang-format on
};

// TODO: should we block raw* functions?
// TODO: Will we ever need to block a subset of functions more than one level deep?
static const sb_block_function sb_restrictedfuncs[] = { { LUA_GNAME, "collectgarbage" },
    { LUA_GNAME, "dofile" }, { LUA_GNAME, "getmetatable" }, { LUA_GNAME, "loadfile" },
    { LUA_GNAME, "load" }, { LUA_GNAME, "pcall" }, { LUA_GNAME, "setmetatable" },
    { LUA_GNAME, "xpcall" },

    { LUA_STRLIBNAME, "rep" }, // TODO:  probably don't need to block this for normal restricted
                               // since we have memory limit
    { NULL, NULL } };

static void sb_loadlibs(lua_State *L, const luaL_Reg *libs)
{
    const luaL_Reg *lib;
    /* "require" functions from 'loadedlibs' and set results to global table */
    for (lib = libs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1); /* remove lib */
    }
}

static void sb_block_functions(lua_State *L, const sb_block_function *funcs)
{
    const sb_block_function *func;

    // set target functions to nil
    lua_pushglobaltable(L);
    for (func = funcs; func->module; func++) {
        lua_pushstring(L, func->module);
        lua_gettable(L, -2); // load module to stack
        lua_pushstring(L, func->name);
        lua_pushnil(L);
        lua_settable(L, -3);
        lua_pop(L, 1); // remove module from the stack
    }
    lua_pop(L, 1); // remove global table
}

void SCLuaSbLoadRestricted(lua_State *L)
{
    sb_loadlibs(L, sb_restrictedlibs);
    sb_block_functions(L, sb_restrictedfuncs);
}

lua_State *SCLuaSbStateNew(uint64_t alloclimit, uint64_t instructionlimit)
{
    SCLuaSbState *sb = SCCalloc(1, sizeof(SCLuaSbState));
    if (sb == NULL) {
        // Out of memory.  Error code?
        return NULL;
    }

    sb->alloc_limit = alloclimit;
    sb->alloc_bytes = 0;
    sb->hook_instruction_count = 100;
    sb->instruction_limit = instructionlimit;

    sb->L = lua_newstate(sb_alloc, sb); /* create state */
    if (sb->L == NULL) {
        // TODO: log or error code?
        SCFree(sb);
        return NULL;
    }

    lua_pushstring(sb->L, SANDBOX_CTX);
    lua_pushlightuserdata(sb->L, sb);
    lua_settable(sb->L, LUA_REGISTRYINDEX);

    lua_sethook(sb->L, sb_hook, LUA_MASKCOUNT, sb->hook_instruction_count);
    return sb->L;
}

static SCLuaSbState *sb_get_ctx(lua_State *L)
{
    lua_pushstring(L, SANDBOX_CTX);
    lua_gettable(L, LUA_REGISTRYINDEX);
    SCLuaSbState *ctx = lua_touserdata(L, -1);
    // TODO:  log if null?
    lua_pop(L, 1);
    return ctx;
}

void SCLuaSbStateClose(lua_State *L)
{
    SCLuaSbState *sb = sb_get_ctx(L);
    lua_close(sb->L);
    SCFree(sb);
}

static void sb_hook(lua_State *L, lua_Debug *ar)
{
    (void)ar;
    SCLuaSbState *sb = sb_get_ctx(L);

    sb->instruction_count += sb->hook_instruction_count;

    if (sb->instruction_limit > 0 && sb->instruction_count > sb->instruction_limit) {
        // TODO: do we care enough for a full traceback here?
        luaL_error(L, "Instruction limit exceeded");
    }
}

void SCLuaSbResetInstructionCounter(lua_State *L)
{
    SCLuaSbState *sb = sb_get_ctx(L);
    if (sb != NULL) {
        sb->instruction_count = 0;
        lua_sethook(L, sb_hook, LUA_MASKCOUNT, sb->hook_instruction_count);
    }
}

void SCLuaSbSetInstructionLimit(lua_State *L, uint64_t instruction_limit)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        ctx->instruction_limit = instruction_limit;
    }
}

static uint64_t sb_getinstructioncount(lua_State *L)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        return ctx->instruction_count;
    }
    return 0;
}

static int sb_Ltotalalloc(lua_State *L)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->alloc_bytes);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int sb_Lgetalloclimit(lua_State *L)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->alloc_limit);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int sb_Lsetalloclimit(lua_State *L)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        ctx->alloc_limit = luaL_checkinteger(L, 1);
    }
    return 0;
}

static int sb_Lgetinstructioncount(lua_State *L)
{
    lua_pushinteger(L, sb_getinstructioncount(L));
    return 1;
}

static int sb_Lgetinstructionlimit(lua_State *L)
{
    SCLuaSbState *ctx = sb_get_ctx(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->instruction_limit);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int sb_Lsetinstructionlimit(lua_State *L)
{
    SCLuaSbSetInstructionLimit(L, luaL_checkinteger(L, 1));
    return 0;
}

static int sb_Lresetinstructioncount(lua_State *L)
{
    SCLuaSbResetInstructionCounter(L);
    return 0;
}

static const luaL_Reg sblib[] = { { "totalalloc", sb_Ltotalalloc },
    { "getalloclimit", sb_Lgetalloclimit }, { "setalloclimit", sb_Lsetalloclimit },
    // { "setlevel", sb_Lsetlevel },
    { "instructioncount", sb_Lgetinstructioncount },
    { "getinstructionlimit", sb_Lgetinstructionlimit },
    { "setinstructionlimit", sb_Lsetinstructionlimit },
    { "resetinstructioncount", sb_Lresetinstructioncount }, { NULL, NULL } };

static int luaopen_sandbox(lua_State *L)
{
    luaL_newlib(L, sblib);
    return 1;
}

#endif
