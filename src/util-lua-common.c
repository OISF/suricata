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

void LuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaPushStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

/** \internal
 *  \brief fill lua stack with payload
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: payload (string), open (bool), close (bool), toserver (bool), toclient (bool)
 */
static int LuaCallbackStreamingBufferPushToStack(lua_State *luastate, const LuaStreamingBuffer *b)
{
    //PrintRawDataFp(stdout, (uint8_t *)b->data, b->data_len);
    lua_pushlstring (luastate, (const char *)b->data, b->data_len);
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_OPEN));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_CLOSE));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_TOSERVER));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_TOCLIENT));
    return 5;
}

/** \internal
 *  \brief Wrapper for getting payload into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackStreamingBuffer(lua_State *luastate)
{
    const LuaStreamingBuffer *b = LuaStateGetStreamingBuffer(luastate);
    if (b == NULL)
        return LuaCallbackError(luastate, "internal error: no buffer");

    return LuaCallbackStreamingBufferPushToStack(luastate, b);
}

/** \internal
 *  \brief fill lua stack with thread info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: thread id (number), thread name (string, thread group name (string)
 */
static int LuaCallbackThreadInfoPushToStackFromThreadVars(lua_State *luastate, const ThreadVars *tv)
{
    unsigned long tid = SCGetThreadIdLong();
    lua_pushinteger (luastate, (lua_Integer)tid);
    lua_pushstring (luastate, tv->name);
    lua_pushstring (luastate, tv->thread_group_name);
    return 3;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackThreadInfo(lua_State *luastate)
{
    const ThreadVars *tv = LuaStateGetThreadVars(luastate);
    if (tv == NULL)
        return LuaCallbackError(luastate, "internal error: no tv");

    return LuaCallbackThreadInfoPushToStackFromThreadVars(luastate, tv);
}

int LuaRegisterFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, LuaCallbackStreamingBuffer);
    lua_setglobal(luastate, "SCStreamingBuffer");

    lua_pushcfunction(luastate, LuaCallbackThreadInfo);
    lua_setglobal(luastate, "SCThreadInfo");
    return 0;
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
