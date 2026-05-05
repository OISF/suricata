/* Copyright (C) 2026 Open Information Security Foundation
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
#include "util-lua-ntp.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "rust.h"

static const char ntp_tx[] = "suricata:ntp:tx";

struct LuaTx {
    NTPTransaction *tx;
};

static int LuaNtpGetTx(lua_State *L)
{
    if (!(LuaStateNeedProto(L, ALPROTO_NTP))) {
        return LuaCallbackError(L, "error: protocol not ntp");
    }
    NTPTransaction *tx = LuaStateGetTX(L);
    if (tx == NULL) {
        return LuaCallbackError(L, "error: no tx available");
    }
    struct LuaTx *ltx = (struct LuaTx *)lua_newuserdata(L, sizeof(*ltx));
    if (ltx == NULL) {
        return LuaCallbackError(L, "error: fail to allocate user data");
    }
    ltx->tx = tx;

    luaL_getmetatable(L, ntp_tx);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaNtpTxGetVersion(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, ntp_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCNtpLuaGetVersion(L, tx->tx);
}

static int LuaNtpTxGetMode(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, ntp_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCNtpLuaGetMode(L, tx->tx);
}

static int LuaNtpTxGetStratum(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, ntp_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCNtpLuaGetStratum(L, tx->tx);
}

static int LuaNtpTxGetReferenceId(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, ntp_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCNtpLuaGetReferenceId(L, tx->tx);
}

static const struct luaL_Reg txlib[] = {
    // clang-format off
    { "mode", LuaNtpTxGetMode },
    { "reference_id", LuaNtpTxGetReferenceId },
    { "stratum", LuaNtpTxGetStratum },
    { "version", LuaNtpTxGetVersion },
    { NULL, NULL, }
    // clang-format on
};

static const struct luaL_Reg ntplib[] = {
    // clang-format off
    { "get_tx", LuaNtpGetTx },
    { NULL, NULL,}
    // clang-format on
};

int SCLuaLoadNtpLib(lua_State *L)
{
    luaL_newmetatable(L, ntp_tx);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, txlib, 0);

    luaL_newlib(L, ntplib);
    return 1;
}
