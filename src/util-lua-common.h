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

int LuaCallbackError(lua_State *luastate, const char *msg);
const char *LuaGetStringArgument(lua_State *luastate, int argc);

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value);
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value);
void LuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len);

int LuaRegisterFunctions(lua_State *luastate);

int LuaStateNeedProto(lua_State *luastate, AppProto alproto);

#endif /* SURICATA_UTIL_LUA_COMMON_H */
