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

#ifndef __UTIL_LUA_H__
#define __UTIL_LUA_H__

#ifdef HAVE_LUA

Packet *LuaStateGetPacket(lua_State *luastate);
void *LuaStateGetTX(lua_State *luastate);

void LuaStateSetPacket(lua_State *luastate, Packet *p);
void LuaStateSetTX(lua_State *luastate, void *tx);

void LuaPrintStack(lua_State *state);

#endif /* HAVE_LUA */

#endif /* __UTIL_LUA_H__ */
