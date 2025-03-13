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

static int DnsGetDnsRrname(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    return SCDnsLuaGetRrname(luastate, tx);
}

static int DnsGetTxid(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    SCDnsLuaGetTxId(luastate, tx);
    return 1;
}

static int DnsGetRcode(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    return SCDnsLuaGetRcode(luastate, tx);
}

static int DnsGetRcodeString(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    return SCDnsLuaGetRcodeString(luastate, tx);
}

static int DnsGetRecursionDesired(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    uint16_t flags = SCDnsTxGetResponseFlags(tx);
    int recursion_desired = flags & 0x0080 ? 1 : 0;
    lua_pushboolean(luastate, recursion_desired);
    return 1;
}

static int DnsGetQueryTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    return SCDnsLuaGetQueryTable(luastate, tx);
}

static int DnsGetAnswerTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    return SCDnsLuaGetAnswerTable(luastate, tx);
}

static int DnsGetAuthorityTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    return SCDnsLuaGetAuthorityTable(luastate, tx);
}

static const struct luaL_Reg dnslib[] = {
    // clang-format off
    { "answers", DnsGetAnswerTable },
    { "authorities", DnsGetAuthorityTable },
    { "queries", DnsGetQueryTable },
    { "rcode", DnsGetRcode },
    { "rcode_string", DnsGetRcodeString },
    { "recursion_desired", DnsGetRecursionDesired },
    { "rrname", DnsGetDnsRrname },
    { "txid", DnsGetTxid },
    { NULL, NULL,},
    // clang-format on
};

int SCLuaLoadDnsLib(lua_State *L)
{
    luaL_newlib(L, dnslib);
    return 1;
}
