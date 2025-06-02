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
#include "threads.h"
#include "threadvars.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-util.h"

#include "lua.h"
#include "lauxlib.h"

/**
 * \brief Get thread information and return as a table
 * \retval 1 table with thread info fields: id, name, thread_group_name
 */
static int LuaUtilThreadInfo(lua_State *luastate)
{
    const ThreadVars *tv = LuaStateGetThreadVars(luastate);
    if (tv == NULL)
        return LuaCallbackError(luastate, "internal error: no tv");

    unsigned long tid = SCGetThreadIdLong();

    lua_newtable(luastate);

    lua_pushstring(luastate, "id");
    lua_pushinteger(luastate, (lua_Integer)tid);
    lua_settable(luastate, -3);

    lua_pushstring(luastate, "name");
    lua_pushstring(luastate, tv->name);
    lua_settable(luastate, -3);

    lua_pushstring(luastate, "group_name");
    lua_pushstring(luastate, tv->thread_group_name);
    lua_settable(luastate, -3);

    return 1;
}

static const struct luaL_Reg utillib[] = {
    { "thread_info", LuaUtilThreadInfo },
    { NULL, NULL },
};

int SCLuaLoadUtilLib(lua_State *L)
{
    luaL_newlib(L, utillib);
    return 1;
}
