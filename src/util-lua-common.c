/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 *
 * Common function for Lua Output
 */

#include "suricata-common.h"

#include "threads.h"
#include "threadvars.h"

#include "output.h"
#include "util-conf.h"

#include "lua.h"

#include "util-lua.h"
#include "util-lua-common.h"

int LuaCallbackError(lua_State *luastate, const char *msg)
{
    lua_pushnil(luastate);
    lua_pushstring(luastate, msg);
    return 2;
}

const char *LuaGetStringArgument(lua_State *luastate, int idx)
{
    /* get argument */
    if (!lua_isstring(luastate, idx))
        return NULL;
    const char *str = lua_tostring(luastate, idx);
    if (str == NULL)
        return NULL;
    if (strlen(str) == 0)
        return NULL;
    return str;
}

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value)
{
    lua_pushstring(luastate, key);
    lua_pushnumber(luastate, value);
    lua_settable(luastate, -3);
}

void LuaPushTableKeyValueBoolean(lua_State *luastate, const char *key, bool value)
{
    lua_pushstring(luastate, key);
    lua_pushboolean(luastate, value);
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value to the stack
 *
 *  If value is NULL, string "(null")" will be put on the stack.
 */
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value)
{
    lua_pushstring(luastate, key);
    lua_pushstring(luastate, value ? value : "(null)");
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value with length to the stack.
 */
void LuaPushTableKeyValueLString(
        lua_State *luastate, const char *key, const char *value, size_t len)
{
    lua_pushstring(luastate, key);
    lua_pushlstring(luastate, value, len);
    lua_settable(luastate, -3);
}

void LuaPushTableKeyValueArray(
        lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaPushStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

int LuaStateNeedProto(lua_State *luastate, AppProto alproto)
{
    AppProto flow_alproto = 0;
    Flow *flow = LuaStateGetFlow(luastate);
    if (flow == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    flow_alproto = flow->alproto;

    return (alproto == flow_alproto);
}
