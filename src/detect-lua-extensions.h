/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifndef SURICATA_DETECT_LUA_EXT_H
#define SURICATA_DETECT_LUA_EXT_H

int LuaRegisterExtensions(lua_State *);

void LuaExtensionsMatchSetup(lua_State *lua_state, DetectLuaData *, DetectEngineThreadCtx *det_ctx,
        Flow *f, Packet *p, const Signature *s, uint8_t flags);

void LuaLoadDatasetLib(lua_State *luastate);

#endif
