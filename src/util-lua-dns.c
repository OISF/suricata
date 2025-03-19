/* Copyright (C) 2014-2025 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 */

#include "suricata-common.h"
#include "util-lua-dns.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "rust.h"

// #define DNS_MT "suricata:dns:tx"
static const char dns_tx[] = "suricata:dns:tx";

struct LuaTx {
    DNSTransaction *tx;
};

static int LuaDnsGetTx(lua_State *L)
{
    if (!(LuaStateNeedProto(L, ALPROTO_DNS))) {
        return LuaCallbackError(L, "error: protocol not dns");
    }
    DNSTransaction *tx = LuaStateGetTX(L);
    if (tx == NULL) {
        return LuaCallbackError(L, "error: no tx available");
    }
    struct LuaTx *ltx = (struct LuaTx *)lua_newuserdata(L, sizeof(*ltx));
    if (ltx == NULL) {
        return LuaCallbackError(L, "error: fail to allocate user data");
    }
    ltx->tx = tx;

    luaL_getmetatable(L, dns_tx);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaDnsTxGetRrname(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetRrname(L, tx->tx);
}

static int LuaDnsTxGetTxid(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetTxId(L, tx->tx);
}

static int LuaDnsTxGetRcode(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetRcode(L, tx->tx);
}

static int LuaDnsTxGetRcodeString(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetRcodeString(L, tx->tx);
}

static int LuaDnsTxGetRecursionDesired(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    uint16_t flags = SCDnsTxGetResponseFlags(tx->tx);
    int recursion_desired = flags & 0x0080 ? 1 : 0;
    lua_pushboolean(L, recursion_desired);
    return 1;
}

static int LuaDnsTxGetQueries(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetQueryTable(L, tx->tx);
}

static int LuaDnsTxGetAnswers(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetAnswerTable(L, tx->tx);
}

static int LuaDnsTxGetAuthorities(lua_State *L)
{
    struct LuaTx *tx = luaL_testudata(L, 1, dns_tx);
    if (tx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    return SCDnsLuaGetAuthorityTable(L, tx->tx);
}

static const struct luaL_Reg txlib[] = {
    // clang-format off
    { "answers", LuaDnsTxGetAnswers },
    { "authorities", LuaDnsTxGetAuthorities },
    { "queries", LuaDnsTxGetQueries },
    { "rcode", LuaDnsTxGetRcode },
    { "rcode_string", LuaDnsTxGetRcodeString },
    { "recursion_desired", LuaDnsTxGetRecursionDesired },
    { "rrname", LuaDnsTxGetRrname },
    { "txid", LuaDnsTxGetTxid },
    { NULL, NULL, }
    // clang-format on
};

static const struct luaL_Reg dnslib[] = {
    // clang-format off
    { "get_tx", LuaDnsGetTx },
    { NULL, NULL,},
    // clang-format on
};

int SCLuaLoadDnsLib(lua_State *L)
{
    luaL_newmetatable(L, dns_tx);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, txlib, 0);

    luaL_newlib(L, dnslib);
    return 1;
}
