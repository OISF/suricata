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

#include "suricata-common.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "util-debug.h"

#include "util-debug.h"
#include "util-validate.h"
#include "util-lua-sandbox.h"

#define SANDBOX_CTX "SANDBOX_CTX"

static void HookFunc(lua_State *L, lua_Debug *ar);
static int OpenSandbox(lua_State *L);

/**
 * Lua allocator function provided to lua_newstate.
 *
 * \param ud The pointer passed to lua_newstate
 * \param ptr Pointer to data being allocated/reallocated/freed
 * \param osize Original size of the block
 * \param nsize Size of the new block
 *
 * See: https://www.lua.org/manual/5.4/manual.html#lua_Alloc
 */
static void *LuaAlloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    (void)ud;
    (void)osize; /* not used */
    SCLuaSbState *ctx = (SCLuaSbState *)ud;
    if (nsize == 0) {
        if (ptr != NULL) {
            // ASSERT: alloc_bytes > osize
            DEBUG_VALIDATE_BUG_ON(ctx->alloc_bytes < osize);
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

/**
 * Function put in place of Lua functions that are blocked.
 *
 * TODO: Might want to create a version of this for each library that
 * has blocked functions, so it can display the name of the
 * library. As it doesn't appear that can be retrieved.
 */
static int LuaBlockedFunction(lua_State *L)
{
    SCLuaSbState *context = SCLuaSbGetContext(L);
    context->blocked_function_error = true;
    lua_Debug ar;
    lua_getstack(L, 0, &ar);
    lua_getinfo(L, "n", &ar);
    if (ar.name) {
        luaL_error(L, "Blocked Lua function called: %s", ar.name);
    } else {
        luaL_error(L, "Blocked Lua function: name not available");
    }
    return -1;
}

/**
 * Check if a Lua function in a specific module is allowed.
 *
 * This is essentially an allow list for Lua functions.
 */
static bool IsAllowed(const char *module, const char *fname)
{
    static const char *base_allowed[] = {
        "assert",
        "ipairs",
        "next",
        "pairs",
        "print",
        "rawequal",
        "rawlen",
        "select",
        "tonumber",
        "tostring",
        "type",
        "warn",
        "rawget",
        "rawset",
        "error",
        NULL,
    };

    /* Allow all. */
    static const char *table_allowed[] = {
        "concat",
        "insert",
        "move",
        "pack",
        "remove",
        "sort",
        "unpack",
        NULL,
    };

    /* Allow all. */
    static const char *string_allowed[] = {
        "byte",
        "char",
        "dump",
        "find",
        "format",
        "gmatch",
        "gsub",
        "len",
        "lower",
        "match",
        "pack",
        "packsize",
        "rep",
        "reverse",
        "sub",
        "unpack",
        "upper",
        NULL,
    };

    /* Allow all. */
    static const char *math_allowed[] = {
        "abs",
        "acos",
        "asin",
        "atan",
        "atan2",
        "ceil",
        "cos",
        "cosh",
        "deg",
        "exp",
        "floor",
        "fmod",
        "frexp",
        "ldexp",
        "log",
        "log10",
        "max",
        "min",
        "modf",
        "pow",
        "rad",
        "random",
        "randomseed",
        "sin",
        "sinh",
        "sqrt",
        "tan",
        "tanh",
        "tointeger",
        "type",
        "ult",
        NULL,
    };

    /* Allow all. */
    static const char *utf8_allowed[] = {
        "offset",
        "len",
        "codes",
        "char",
        "codepoint",
        NULL,
    };

    const char **allowed = NULL;

    if (strcmp(module, LUA_GNAME) == 0) {
        allowed = base_allowed;
    } else if (strcmp(module, LUA_TABLIBNAME) == 0) {
        allowed = table_allowed;
    } else if (strcmp(module, LUA_STRLIBNAME) == 0) {
        allowed = string_allowed;
    } else if (strcmp(module, LUA_MATHLIBNAME) == 0) {
        allowed = math_allowed;
    } else if (strcmp(module, LUA_UTF8LIBNAME) == 0) {
        allowed = utf8_allowed;
    } else {
        /* This is a programming error. */
        FatalError("Unknown Lua module %s", module);
    }

    if (allowed) {
        for (int i = 0; allowed[i] != NULL; i++) {
            if (strcmp(allowed[i], fname) == 0) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Set of libs that are allowed and loaded into the Lua state.
 */
static const luaL_Reg AllowedLibs[] = {
    // clang-format off
    { LUA_GNAME, luaopen_base },
    { LUA_TABLIBNAME, luaopen_table },
    { LUA_STRLIBNAME, luaopen_string },
    { LUA_MATHLIBNAME, luaopen_math },
    { LUA_UTF8LIBNAME, luaopen_utf8 },
    { NULL, NULL }
    // clang-format on
};

/**
 * Load allowed Lua libraries into the state.
 *
 * Functions from each library that are not in the allowed list are
 * replaced with LuaBlockedFunction.
 */
void SCLuaSbLoadLibs(lua_State *L)
{
    const luaL_Reg *lib;

    for (lib = AllowedLibs; lib->func; lib++) {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1);
        /* Iterate over all the functions in the just loaded table and
         * replace functions now on the allow list with our blocked
         * function placeholder. */
        lua_getglobal(L, lib->name);
        lua_pushnil(L);
        while (lua_next(L, -2)) {
            if (lua_type(L, -1) == LUA_TFUNCTION) {
                const char *name = lua_tostring(L, -2);
                if (!IsAllowed(lib->name, name)) {
                    SCLogDebug("Blocking Lua function %s.%s", lib->name, name);
                    lua_pushstring(L, name);
                    lua_pushcfunction(L, LuaBlockedFunction);
                    lua_settable(L, -5);
                } else {
                    SCLogDebug("Allowing Lua function %s.%s", lib->name, name);
                }
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
}

/**
 * \brief Allocate a new Lua sandbox.
 *
 * \returns An allocated sandbox state or NULL if memory allocation
 *     fails.
 */
lua_State *SCLuaSbStateNew(uint64_t alloclimit, uint64_t instructionlimit)
{
    SCLuaSbState *sb = SCCalloc(1, sizeof(SCLuaSbState));
    if (sb == NULL) {
        return NULL;
    }

    sb->alloc_limit = alloclimit;
    sb->alloc_bytes = 0;
    sb->hook_instruction_count = 100;
    sb->instruction_limit = instructionlimit;

    sb->L = lua_newstate(LuaAlloc, sb); /* create state */
    if (sb->L == NULL) {
        SCFree(sb);
        return NULL;
    }

    lua_pushstring(sb->L, SANDBOX_CTX);
    lua_pushlightuserdata(sb->L, sb);
    lua_settable(sb->L, LUA_REGISTRYINDEX);

    lua_sethook(sb->L, HookFunc, LUA_MASKCOUNT, sb->hook_instruction_count);
    return sb->L;
}

/**
 * Get the Suricata Lua sandbox context from the lua_State.
 *
 * Note: May return null if this Lua state was not allocated from the
 * sandbox.
 */
SCLuaSbState *SCLuaSbGetContext(lua_State *L)
{
    lua_pushstring(L, SANDBOX_CTX);
    lua_gettable(L, LUA_REGISTRYINDEX);
    SCLuaSbState *ctx = lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ctx;
}

void SCLuaSbStateClose(lua_State *L)
{
    SCLuaSbState *sb = SCLuaSbGetContext(L);
    lua_close(sb->L);
    SCFree(sb);
}

/**
 * Lua debugging hook, but used here for instruction limit counting.
 */
static void HookFunc(lua_State *L, lua_Debug *ar)
{
    (void)ar;
    SCLuaSbState *sb = SCLuaSbGetContext(L);

    sb->instruction_count += sb->hook_instruction_count;

    if (sb->instruction_limit > 0 && sb->instruction_count > sb->instruction_limit) {
        sb->instruction_count_error = true;
        luaL_error(L, "instruction limit exceeded");
    }
}

/**
 * Reset the instruction counter for the provided state.
 */
void SCLuaSbResetInstructionCounter(lua_State *L)
{
    SCLuaSbState *sb = SCLuaSbGetContext(L);
    if (sb != NULL) {
        sb->blocked_function_error = false;
        sb->instruction_count_error = false;
        sb->instruction_count = 0;
        lua_sethook(L, HookFunc, LUA_MASKCOUNT, sb->hook_instruction_count);
    }
}

static void SetInstructionCount(lua_State *L, uint64_t instruction_limit)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        ctx->instruction_limit = instruction_limit;
    }
}

static uint64_t GetInstructionCount(lua_State *L)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        return ctx->instruction_count;
    }
    return 0;
}

static int L_TotalAlloc(lua_State *L)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->alloc_bytes);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int L_GetAllocLimit(lua_State *L)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->alloc_limit);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int L_SetAllocLimit(lua_State *L)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        ctx->alloc_limit = luaL_checkinteger(L, 1);
    }
    return 0;
}

static int L_GetInstructionCount(lua_State *L)
{
    lua_pushinteger(L, GetInstructionCount(L));
    return 1;
}

static int L_GetInstructionLimit(lua_State *L)
{
    SCLuaSbState *ctx = SCLuaSbGetContext(L);
    if (ctx != NULL) {
        lua_pushinteger(L, ctx->instruction_limit);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int L_SetInstructionLimit(lua_State *L)
{
    SetInstructionCount(L, luaL_checkinteger(L, 1));
    return 0;
}

static int L_ResetInstructionCount(lua_State *L)
{
    SCLuaSbResetInstructionCounter(L);
    return 0;
}

static const luaL_Reg sblib[] = {
    // clang-format off
    { "totalalloc", L_TotalAlloc },
    { "getalloclimit", L_GetAllocLimit },
    { "setalloclimit", L_SetAllocLimit },
    { "instructioncount", L_GetInstructionCount },
    { "getinstructionlimit", L_GetInstructionLimit },
    { "setinstructionlimit", L_SetInstructionLimit },
    { "resetinstructioncount", L_ResetInstructionCount },
    { NULL, NULL }
    // clang-format on
};

static int OpenSandbox(lua_State *L)
{
    luaL_newlib(L, sblib);
    return 1;
}
