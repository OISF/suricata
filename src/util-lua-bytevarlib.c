/* Copyright (C) 2025 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect-byte.h"
#include "util-lua-common.h"
#include "util-lua-bytevarlib.h"
#include "util-lua.h"
#include "detect-lua.h"
#include "detect-lua-extensions.h"

#include "lauxlib.h"

static const char suricata_bytevar_mt[] = "suricata:bytevar:mt";

static DetectLuaData *GetLuaData(lua_State *luastate)
{
    DetectLuaData *ld;
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    return ld;
}

static int LuaBytevarMap(lua_State *L)
{
    const Signature *s = lua_touserdata(L, -2);
    const char *name = luaL_checkstring(L, -1);
    DetectLuaData *ld = GetLuaData(L);

    /* Is this name already mapped? */
    for (uint16_t i = 0; i < ld->bytevars; i++) {
        if (strcmp(ld->bytevar[i].name, name) == 0) {
            lua_pushinteger(L, ld->bytevar[i].id);
            return 1;
        }
    }

    if (ld->bytevars == DETECT_LUA_MAX_BYTEVARS) {
        luaL_error(L, "too many bytevars mapped");
    }

    DetectByteIndexType idx;
    if (!DetectByteRetrieveSMVar(name, s, -1, &idx)) {
        return luaL_error(L, "unknown byte_extract or byte_math variable: %s", name);
    }

    ld->bytevar[ld->bytevars].name = SCStrdup(name);
    if (ld->bytevar[ld->bytevars].name == NULL) {
        luaL_error(L, "failed to allocate memory for bytevar name: %s", name);
    }
    ld->bytevar[ld->bytevars++].id = idx;

    return 1;
}

static int LuaBytevarGet(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    DetectLuaData *ld = GetLuaData(L);
    if (ld == NULL) {
        return luaL_error(L, "internal error: no lua data");
    }

    for (uint16_t i = 0; i < ld->bytevars; i++) {
        if (strcmp(ld->bytevar[i].name, name) == 0) {
            uint32_t *bytevar_id = lua_newuserdata(L, sizeof(*bytevar_id));
            *bytevar_id = ld->bytevar[i].id;
            luaL_getmetatable(L, suricata_bytevar_mt);
            lua_setmetatable(L, -2);
            return 1;
        }
    }

    return luaL_error(L, "unknown bytevar: %s", name);
}

static int LuaBytevarValue(lua_State *L)
{
    uint32_t *bytevar_id = luaL_checkudata(L, 1, suricata_bytevar_mt);
    DetectEngineThreadCtx *det_ctx = LuaStateGetDetCtx(L);
    if (det_ctx == NULL) {
        return LuaCallbackError(L, "internal error: no det_ctx");
    }
    lua_pushinteger(L, det_ctx->byte_values[*bytevar_id]);
    return 1;
}

static const luaL_Reg bytevarlib[] = {
    // clang-format off
    { "map", LuaBytevarMap, },
    { "get", LuaBytevarGet, },
    { NULL, NULL, },
    // clang-format on
};

static const luaL_Reg bytevarmt[] = {
    // clang-format off
    { "value", LuaBytevarValue, },
    { NULL, NULL, },
    // clang-format on
};

int LuaLoadBytevarLib(lua_State *L)
{
    luaL_newmetatable(L, suricata_bytevar_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, bytevarmt, 0);

    luaL_newlib(L, bytevarlib);
    return 1;
}
