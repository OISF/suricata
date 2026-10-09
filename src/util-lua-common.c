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

void *SCLuaNewUserData(lua_State *L, uint32_t type_id, size_t size)
{
    uint8_t *block = (uint8_t *)lua_newuserdata(L, sizeof(SCLuaUserDataHeader) + size);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    h->magic = SCLUA_UD_MAGIC;
    h->type_id = type_id;
    return block + sizeof(SCLuaUserDataHeader);
}

static uint8_t *SCLuaUserDataPayload(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    void *block = luaL_testudata(L, idx, mt);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    if (h->magic != SCLUA_UD_MAGIC || h->type_id != type_id) {
        return NULL;
    }
    return (uint8_t *)block + sizeof(SCLuaUserDataHeader);
}

void *SCLuaCheckUserData(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    uint8_t *block = (uint8_t *)luaL_checkudata(L, idx, mt);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    if (h->magic != SCLUA_UD_MAGIC || h->type_id != type_id) {
        luaL_error(L, "invalid handle: type mismatch");
        /* luaL_error raises; the return keeps the fail-closed path
         * explicit if it ever did not */
        return NULL;
    }
    return block + sizeof(SCLuaUserDataHeader);
}

void *SCLuaTestUserData(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    return SCLuaUserDataPayload(L, idx, mt, type_id);
}

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

/*
 * Protocol check for the tx libs. Returns a plain boolean: 1 when the
 * flow's app protocol matches, 0 otherwise (including the no-flow
 * case). Errors are reported by the callers, so nothing is pushed on
 * the stack. The previous implementation returned
 * LuaCallbackError's 2 for the no-flow case, which the boolean callers
 * treat as a protocol match.
 */
int LuaStateNeedProto(lua_State *luastate, AppProto alproto)
{
    Flow *flow = LuaStateGetFlow(luastate);
    if (flow == NULL)
        return 0;

    return (alproto == flow->alproto);
}
