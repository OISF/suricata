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
#include "app-layer-protos.h"
#include "flow-var.h"
#include "lauxlib.h"
#include "util-debug.h"
#include "util-lua-common.h"
#include "util-lua-flowvarlib.h"
#include "util-lua.h"
#include "util-var-name.h"
#include "detect-lua.h"
#include "detect-lua-extensions.h"

static const char suricata_flowvar_mt[] = "suricata:flowvar:mt";

static DetectLuaData *GetLuaData(lua_State *luastate)
{
    DetectLuaData *ld;
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    return ld;
}

/**
 * \brief Register a flowvar.
 *
 * Ensures that a flowvar exists for the provided name, will be
 * created if needed.
 *
 * The flowvar ID is returned, however as this is most likely to be
 * used in the scripts "init" method, this ID is unlikely to be used.
 */
static int LuaFlowvarRegister(lua_State *L)
{
    DetectLuaData *ld = GetLuaData(L);
    const char *name = luaL_checkstring(L, 1);
    uint32_t *flowvar_id = lua_newuserdata(L, sizeof(*flowvar_id));
    *flowvar_id = VarNameStoreRegister(name, VAR_TYPE_FLOW_VAR);
    if (*flowvar_id == 0) {
        return luaL_error(L, "failed to register flowvar");
    }
    ld->flowvar[ld->flowvars++] = *flowvar_id;

    luaL_getmetatable(L, suricata_flowvar_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaFlowvarGet(lua_State *L)
{
    const char *name = luaL_checkstring(L, 1);
    uint32_t *flowvar_id = lua_newuserdata(L, sizeof(*flowvar_id));
    *flowvar_id = VarNameStoreLookupByName(name, VAR_TYPE_FLOW_VAR);
    if (*flowvar_id == 0) {
        return luaL_error(L, "flowvar does not exist");
    }

    luaL_getmetatable(L, suricata_flowvar_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaFlowvarValue(lua_State *L)
{
    uint32_t *flowvar_id = luaL_checkudata(L, 1, suricata_flowvar_mt);
    Flow *f = LuaStateGetFlow(L);
    if (f == NULL) {
        return LuaCallbackError(L, "flow is NULL");
    }
    FlowVar *fv = FlowVarGet(f, *flowvar_id);
    if (fv == NULL) {
        lua_pushnil(L);
    } else {
        LuaPushStringBuffer(
                L, (const uint8_t *)fv->data.fv_str.value, (size_t)fv->data.fv_str.value_len);
    }
    return 1;
}

static int LuaFlowvarSet(lua_State *L)
{
    const char *value = luaL_checkstring(L, 2);
    const int len = (int)luaL_checkinteger(L, 3);
    uint32_t *flowvar_id = luaL_checkudata(L, 1, suricata_flowvar_mt);
    Flow *f = LuaStateGetFlow(L);
    if (f == NULL) {
        return luaL_error(L, "no flow");
    }

    uint8_t *buf = SCMalloc(len + 1);
    if (buf == NULL) {
        return luaL_error(L, "alloc failure");
    }
    memcpy(buf, value, len);
    buf[len] = '\0';
    FlowVarAddIdValue(f, *flowvar_id, buf, (uint16_t)len);

    return 1;
}

static const luaL_Reg flowvarlib[] = {
    // clang-format off
    { "register", LuaFlowvarRegister, },
    { "get", LuaFlowvarGet },
    { NULL, NULL, },
    // clang-format on
};

static const luaL_Reg flowvarmt[] = {
    // clang-format off
    { "value", LuaFlowvarValue, },
    { "set", LuaFlowvarSet, },
    { NULL, NULL, },
    // clang-format on
};

int LuaLoadFlowvarLib(lua_State *L)
{
    luaL_newmetatable(L, suricata_flowvar_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, flowvarmt, 0);

    luaL_newlib(L, flowvarlib);
    return 1;
}
