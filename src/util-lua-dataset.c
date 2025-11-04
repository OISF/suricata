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

/**
 * \file
 *
 * Dataset API for Lua.
 *
 * local dataset = require("suricata.dataset")
 */

#include "suricata-common.h"

#include "util-lua-dataset.h"

#include "app-layer-protos.h" /* Required by util-lua-common. */
#include "util-lua-common.h"
#include "util-lua.h"
#include "util-debug.h"

#include "datasets.h"

struct LuaDataset {
    Dataset *set;
};

static int LuaDatasetGC(lua_State *luastate)
{
    SCLogDebug("gc:start");
    struct LuaDataset *s = (struct LuaDataset *)lua_touserdata(luastate, 1);
    SCLogDebug("deref %s", s->set->name);
    s->set = NULL;
    SCLogDebug("gc:done");
    return 0;
}

static int LuaDatasetGetRef(lua_State *luastate)
{
    SCLogDebug("get");
    struct LuaDataset *s = (struct LuaDataset *)lua_touserdata(luastate, 1);
    if (s == NULL) {
        LUA_ERROR("dataset is not initialized");
    }

    const char *name = lua_tostring(luastate, 2);
    if (name == NULL) {
        LUA_ERROR("null string");
    }

    Dataset *dataset = DatasetFind(name, DATASET_TYPE_STRING);
    if (dataset == NULL) {
        LUA_ERROR("dataset not found");
    }
    s->set = dataset;
    return 0;
}

static int LuaDatasetAdd(lua_State *luastate)
{
    SCLogDebug("add:start");
    struct LuaDataset *s = (struct LuaDataset *)lua_touserdata(luastate, 1);
    if (s == NULL) {
        LUA_ERROR("dataset is not initialized");
    }
    if (!lua_isstring(luastate, 2)) {
        LUA_ERROR("1st arg is not a string");
    }
    if (!lua_isnumber(luastate, 3)) {
        LUA_ERROR("2nd arg is not a number");
    }

    const uint8_t *str = (const uint8_t *)lua_tostring(luastate, 2);
    if (str == NULL) {
        LUA_ERROR("1st arg is not null string");
    }

    uint32_t str_len = lua_tonumber(luastate, 3);

    int r = SCDatasetAdd(s->set, (const uint8_t *)str, str_len);
    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)r);
    SCLogDebug("add:end");
    return 1;
}

static int LuaDatasetNew(lua_State *luastate)
{
    SCLogDebug("new:start");
    struct LuaDataset *s = (struct LuaDataset *)lua_newuserdata(luastate, sizeof(*s));
    if (s == NULL) {
        LUA_ERROR("failed to get userdata");
    }
    luaL_getmetatable(luastate, "dataset::metatable");
    lua_setmetatable(luastate, -2);
    SCLogDebug("new:done");
    return 1;
}

// clang-format off
static const luaL_Reg datasetlib[] = {
    { "new", LuaDatasetNew },
    { "get", LuaDatasetGetRef },
    { "add", LuaDatasetAdd },
    { "__gc", LuaDatasetGC },
    { NULL, NULL }
};
// clang-format on

int LuaLoadDatasetLib(lua_State *luastate)
{
    luaL_newmetatable(luastate, "dataset::metatable");
    lua_pushvalue(luastate, -1);
    lua_setfield(luastate, -2, "__index");
    luaL_setfuncs(luastate, datasetlib, 0);
    luaL_newlib(luastate, datasetlib);

    return 1;
}
