/* Copyright (C) 2014 Open Information Security Foundation
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
 */

#ifndef SURICATA_UTIL_LUA_COMMON_H
#define SURICATA_UTIL_LUA_COMMON_H

#define DEFAULT_LUA_ALLOC_LIMIT       500000
#define DEFAULT_LUA_INSTRUCTION_LIMIT 500000

/*
 * The libs validate their handles with luaL_checkudata(), i.e. by
 * metatable identity only. In unsandboxed states setmetatable() /
 * debug.setmetatable() is reachable, so a script can give one lib's
 * userdata another lib's metatable and the FFI code would re-cast the
 * payload (type confusion / wrong drop size). Each library userdata
 * therefore carries an immutable header with a type id that the
 * helpers verify next to the metatable; a forged handle fails closed.
 */
#define SCLUA_UD_MAGIC 0x534C5541u /* "SLUA" */

typedef struct SCLuaUserDataHeader_ {
    uint32_t magic;
    uint32_t type_id;
} SCLuaUserDataHeader;

enum SCLuaUserDataTypes {
    SCLUA_TUD_INVALID = 0,
    SCLUA_TUD_SHA256 = 1,
    SCLUA_TUD_SHA1,
    SCLUA_TUD_MD5,
    SCLUA_TUD_FLOWVAR,
    SCLUA_TUD_FLOWINT,
    SCLUA_TUD_BYTEVAR,
    SCLUA_TUD_DATASET,
    SCLUA_TUD_RULE,
    SCLUA_TUD_FILE,
    SCLUA_TUD_FLOW,
    SCLUA_TUD_PACKET,
    SCLUA_TUD_TLS_STATE,
    SCLUA_TUD_HTTP_TX,
    SCLUA_TUD_DNS_TX,
    SCLUA_TUD_SMTP_TX,
    SCLUA_TUD_SSH_TX,
    SCLUA_TUD_NTP_TX,
    SCLUA_TUD_JA3_TX,
    SCLUA_TUD_DNP3_POINTS,
};

/*
 * Allocate a library userdata with the type header. Returns the start
 * of the payload area (size bytes) and leaves the object on the stack;
 * set the metatable afterwards.
 */
void *SCLuaNewUserData(lua_State *L, uint32_t type_id, size_t size);

/*
 * Verify the object at idx has metatable mt and type id type_id, error
 * otherwise. Returns the payload start; the object is left as-is.
 */
void *SCLuaCheckUserData(lua_State *L, int idx, const char *mt, uint32_t type_id);

/*
 * As SCLuaCheckUserData but never raises: returns the payload start,
 * or NULL when the object is absent, untagged or of another type.
 * For __gc handlers, where a forged handle must be skipped, not raised
 * on.
 */
void *SCLuaTestUserData(lua_State *L, int idx, const char *mt, uint32_t type_id);

int LuaCallbackError(lua_State *luastate, const char *msg);
const char *LuaGetStringArgument(lua_State *luastate, int argc);

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value);
void LuaPushTableKeyValueBoolean(lua_State *luastate, const char *key, bool value);
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value);
void LuaPushTableKeyValueLString(
        lua_State *luastate, const char *key, const char *value, size_t len);
void LuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len);

int LuaStateNeedProto(lua_State *luastate, AppProto alproto);

/* hack to please scan-build. Even though LuaCallbackError *always*
 * returns 2, scan-build doesn't accept it and generates false
 * positives */
#define LUA_ERROR(msg)                                                                             \
    LuaCallbackError(luastate, (msg));                                                             \
    return 2

#endif /* SURICATA_UTIL_LUA_COMMON_H */
