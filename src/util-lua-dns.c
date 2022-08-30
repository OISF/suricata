/* Copyright (C) 2014-2022 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "rust.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-dns.h"

static int DnsGetDnsRrname(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    return rs_dns_lua_get_rrname(luastate, tx);
}

static int DnsGetTxid(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    rs_dns_lua_get_tx_id(luastate, tx);
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
    return rs_dns_lua_get_rcode(luastate, tx);
}

static int DnsGetRecursionDesired(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    uint16_t flags = rs_dns_tx_get_response_flags(tx);
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
    return rs_dns_lua_get_query_table(luastate, tx);
}

static int DnsGetAnswerTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    return rs_dns_lua_get_answer_table(luastate, tx);
}

static int DnsGetAuthorityTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    return rs_dns_lua_get_authority_table(luastate, tx);
}

/** \brief register http lua extensions in a luastate */
int LuaRegisterDnsFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, DnsGetDnsRrname);
    lua_setglobal(luastate, "DnsGetDnsRrname");

    lua_pushcfunction(luastate, DnsGetQueryTable);
    lua_setglobal(luastate, "DnsGetQueries");

    lua_pushcfunction(luastate, DnsGetAnswerTable);
    lua_setglobal(luastate, "DnsGetAnswers");

    lua_pushcfunction(luastate, DnsGetAuthorityTable);
    lua_setglobal(luastate, "DnsGetAuthorities");

    lua_pushcfunction(luastate, DnsGetTxid);
    lua_setglobal(luastate, "DnsGetTxid");

    lua_pushcfunction(luastate, DnsGetRcode);
    lua_setglobal(luastate, "DnsGetRcode");

    lua_pushcfunction(luastate, DnsGetRecursionDesired);
    lua_setglobal(luastate, "DnsGetRecursionDesired");
    return 0;
}

#endif /* HAVE_LUA */
