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

/*
 * The handle stores a copy of the set name, not a Dataset* pointer.
 * The engine frees and re-creates sets on rule reload
 * (DatasetPostReloadCleanup) while output states keep running; a cached
 * pointer would dangle. Re-resolving the name on every use follows the
 * reload to the new set and fails cleanly if the set is gone.
 */
struct LuaDataset {
    char name[DATASET_NAME_MAX_LEN + 1];
};

static int LuaDatasetGC(lua_State *luastate)
{
    SCLogDebug("gc:start");
    struct LuaDataset *s = (struct LuaDataset *)luaL_testudata(luastate, 1, "dataset::metatable");
    if (s != NULL) {
        s->name[0] = '\0';
    }
    SCLogDebug("gc:done");
    return 0;
}

static int LuaDatasetGetRef(lua_State *luastate)
{
    SCLogDebug("get");
    struct LuaDataset *s = (struct LuaDataset *)luaL_checkudata(luastate, 1, "dataset::metatable");

    const char *name = lua_tostring(luastate, 2);
    if (name == NULL) {
        LUA_ERROR("null string");
    }

    if (DatasetFind(name, DATASET_TYPE_STRING) == NULL) {
        LUA_ERROR("dataset not found");
    }
    if (strlen(name) >= sizeof(s->name)) {
        LUA_ERROR("dataset name too long");
    }
    snprintf(s->name, sizeof(s->name), "%s", name);
    return 0;
}

static int LuaDatasetAdd(lua_State *luastate)
{
    SCLogDebug("add:start");
    struct LuaDataset *s = luaL_checkudata(luastate, 1, "dataset::metatable");
    if (s->name[0] == '\0') {
        LUA_ERROR("dataset is not initialized (call :get first)");
    }

    /* re-resolve the set: the cached name is the only engine state we
     * hold, so a set freed and reloaded under the same name is followed */
    Dataset *dataset = DatasetFind(s->name, DATASET_TYPE_STRING);
    if (dataset == NULL) {
        LUA_ERROR("dataset not found");
    }

    size_t real_len = 0;
    const uint8_t *str = (const uint8_t *)lua_tolstring(luastate, 2, &real_len);
    if (str == NULL) {
        LUA_ERROR("1st arg is not a string");
    }

    if (!lua_isinteger(luastate, 3)) {
        LUA_ERROR("2nd arg is not a string");
    }
    lua_Integer n = lua_tointeger(luastate, 3);
    if (n < 0 || (size_t)n > real_len) {
        LUA_ERROR("length out of range for supplied string");
    }
    uint32_t str_len = (uint32_t)n;

    int r = DatasetAdd(dataset, str, str_len);
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
    memset(s, 0, sizeof(*s));
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
