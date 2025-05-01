/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * Functions to expose to the lua scripts.
 */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"

#include "flow.h"

#include "util-debug.h"

#include "detect-lua.h"

#include "app-layer-parser.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-ja3.h"
#include "util-lua-tls.h"
#include "util-lua-smtp.h"
#include "util-lua-dnp3.h"
#include "detect-lua-extensions.h"

/* Lua registry key for DetectLuaData. */
const char luaext_key_ld[] = "suricata:luadata";

static int GetLuaData(lua_State *luastate, DetectLuaData **ret_ld)
{
    *ret_ld = NULL;

    DetectLuaData *ld;
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    if (ld == NULL) {
        LUA_ERROR("internal error: no ld");
    }
    *ret_ld = ld;
    return 0;
}

static int LuaGetByteVar(lua_State *luastate)
{
    DetectLuaData *ld = NULL;
    DetectEngineThreadCtx *det_ctx = LuaStateGetDetCtx(luastate);

    if (det_ctx == NULL)
        return LuaCallbackError(luastate, "internal error: no ldet_ctx");

    int ret = GetLuaData(luastate, &ld);
    if (ret != 0)
        return ret;

    if (!lua_isnumber(luastate, 1)) {
        LUA_ERROR("bytevar id not a number");
    }
    int id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUA_MAX_BYTEVARS) {
        LUA_ERROR("bytevar id out of range");
    }
    uint32_t idx = ld->bytevar[id];

    lua_pushinteger(luastate, det_ctx->byte_values[idx]);

    return 1;
}

void LuaExtensionsMatchSetup(lua_State *lua_state, DetectLuaData *ld,
        DetectEngineThreadCtx *det_ctx, Flow *f, Packet *p, const Signature *s, uint8_t flags)
{
    SCLogDebug("det_ctx %p, f %p", det_ctx, f);

    LuaStateSetSignature(lua_state, s);
    LuaStateSetFlow(lua_state, f);
    LuaStateSetDetCtx(lua_state, det_ctx);

    if (det_ctx->tx_id_set) {
        if (f && f->alstate) {
            void *txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, det_ctx->tx_id);
            if (txptr) {
                LuaStateSetTX(lua_state, txptr, det_ctx->tx_id);
            }
        }
    }

    if (p != NULL)
        LuaStateSetPacket(lua_state, p);

    LuaStateSetDirection(lua_state, (flags & STREAM_TOSERVER));
}

/**
 *  \brief Register Suricata Lua functions
 */
int LuaRegisterExtensions(lua_State *lua_state)
{
    lua_pushcfunction(lua_state, LuaGetByteVar);
    lua_setglobal(lua_state, "SCByteVarGet");

    LuaRegisterFunctions(lua_state);
    LuaRegisterJa3Functions(lua_state);
    LuaRegisterTlsFunctions(lua_state);
    LuaRegisterSmtpFunctions(lua_state);
    return 0;
}
