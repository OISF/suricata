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
#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-filelib.h"

#include "lua.h"
#include "lauxlib.h"

static const char file_mt[] = "suricata:file:mt";

struct LuaFile {
    File *file;
};

static int LuaFileGetFile(lua_State *L)
{
    File *file = LuaStateGetFile(L);
    if (file == NULL) {
        return LuaCallbackError(L, "error: no file found");
    }

    struct LuaFile *lua_file = (struct LuaFile *)lua_newuserdata(L, sizeof(*lua_file));
    if (lua_file == NULL) {
        return LuaCallbackError(L, "error: fail to allocate user data");
    }
    lua_file->file = file;

    luaL_getmetatable(L, file_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaFileGetFileId(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;
    lua_pushinteger(L, file->file_store_id);

    return 1;
}

static int LuaFileGetTxId(lua_State *L)
{
    lua_Integer tx_id = LuaStateGetTxId(L);
    lua_pushinteger(L, tx_id);

    return 1;
}

static int LuaFileGetName(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;
    lua_pushlstring(L, (char *)file->name, file->name_len);

    return 1;
}

static int LuaFileGetSize(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;
    lua_pushinteger(L, FileTrackedSize(file));

    return 1;
}

static int LuaFileGetMagic(lua_State *L)
{
#ifdef HAVE_MAGIC
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;
    if (file->magic != NULL) {
        lua_pushstring(L, file->magic);
    } else {
        lua_pushnil(L);
    }
#else
    lua_pushnil(L);
#endif

    return 1;
}

static void PushHex(lua_State *L, const uint8_t *buf, size_t len)
{
    /* Large enough for sha256. */
    char hex[65] = "";
    for (size_t i = 0; i < len; i++) {
        char one[3] = "";
        snprintf(one, sizeof(one), "%02x", buf[i]);
        strlcat(hex, one, sizeof(hex));
    }

    lua_pushstring(L, hex);
}

static int LuaFileGetMd5(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;

    if (file->flags & FILE_MD5) {
        PushHex(L, file->md5, sizeof(file->md5));
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int LuaFileGetSha1(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;

    if (file->flags & FILE_SHA1) {
        PushHex(L, file->sha1, sizeof(file->sha1));
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int LuaFileGetSha256(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;

    if (file->flags & FILE_SHA256) {
        PushHex(L, file->sha256, sizeof(file->sha256));
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int LuaFileGetState(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;

    const char *state = "UNKNOWN";
    switch (file->state) {
        case FILE_STATE_CLOSED:
            state = "CLOSED";
            break;
        case FILE_STATE_TRUNCATED:
            state = "TRUNCATED";
            break;
        case FILE_STATE_ERROR:
            state = "ERROR";
            break;
        case FILE_STATE_OPENED:
            state = "OPENED";
            break;
        case FILE_STATE_NONE:
            state = "NONE";
            break;
        case FILE_STATE_MAX:
            break;
    }

    lua_pushstring(L, state);

    return 1;
}

static int LuaFileIsStored(lua_State *L)
{
    struct LuaFile *lua_file = luaL_checkudata(L, 1, file_mt);
    const File *file = lua_file->file;
    lua_pushboolean(L, file->flags & FILE_STORED);

    return 1;
}

static const struct luaL_Reg filelib[] = {
    { "get_state", LuaFileGetState },
    { "is_stored", LuaFileIsStored },
    { "file_id", LuaFileGetFileId },
    { "tx_id", LuaFileGetTxId },
    { "name", LuaFileGetName },
    { "size", LuaFileGetSize },
    { "magic", LuaFileGetMagic },
    { "md5", LuaFileGetMd5 },
    { "sha1", LuaFileGetSha1 },
    { "sha256", LuaFileGetSha256 },
    { NULL, NULL },
};

static const struct luaL_Reg filemodlib[] = {
    { "get_file", LuaFileGetFile },
    { NULL, NULL },
};

int SCLuaLoadFileLib(lua_State *L)
{
    luaL_newmetatable(L, file_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, filelib, 0);

    luaL_newlib(L, filemodlib);

    return 1;
}
