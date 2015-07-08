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
#include "app-layer-dns-common.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
#include "util-lua-common.h"

static int DnsGetDnsRrname(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &tx->query_list, next) {
        char *c;
        size_t input_len;
        c = BytesToString((uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry)), query->len);
        if (c != NULL) {
            int ret;
            input_len = strlen(c);
            /* sanity check */
            if (input_len > (size_t)(2 * query->len)) {
                SCFree(c);
                return LuaCallbackError(luastate, "invalid length");
            }
            ret = LuaPushStringBuffer(luastate, (uint8_t *)c, input_len);
            SCFree(c);
            return ret;
        }
    }

    return LuaCallbackError(luastate, "no query");
}

static int DnsGetTxid(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    lua_pushinteger(luastate, tx->tx_id);
    return 1;
}

static int DnsGetRcode(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (tx->rcode) {
        char rcode[16] = "";
        DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
        return LuaPushStringBuffer(luastate, (const uint8_t *)rcode, strlen(rcode));
    } else {
        return 0;
    }
}

static int DnsGetRecursionDesired(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    lua_pushboolean(luastate, tx->recursion_desired);
    return 1;
}

static int DnsGetQueryTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    uint32_t u = 0;
    lua_newtable(luastate);
    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &tx->query_list, next) {
        lua_pushinteger(luastate, u++);

        lua_newtable(luastate);
        char record[16] = "";
        DNSCreateTypeString(query->type, record, sizeof(record));
        lua_pushstring(luastate, "type");
        lua_pushstring(luastate, record);
        lua_settable(luastate, -3);

        {
            char *c;
            size_t input_len;
            c = BytesToString((uint8_t *)((uint8_t *)query + sizeof(DNSQueryEntry)), query->len);
            if (c != NULL) {
                input_len = strlen(c);
                /* sanity check */
                if (input_len > (size_t)(2 * query->len)) {
                    SCFree(c);
                    return LuaCallbackError(luastate, "invalid length");
                }
                lua_pushstring(luastate, "rrname");
                LuaPushStringBuffer(luastate, (uint8_t *)c, input_len);
                lua_settable(luastate, -3);
                SCFree(c);
            }
        }


        lua_settable(luastate, -3);
    }

    return 1;
}

static int DnsGetAnswerTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    uint32_t u = 0;
    lua_newtable(luastate);
    DNSAnswerEntry *answer = NULL;
    TAILQ_FOREACH(answer, &tx->answer_list, next) {
        lua_pushinteger(luastate, u++);

        lua_newtable(luastate);
        char record[16] = "";
        DNSCreateTypeString(answer->type, record, sizeof(record));
        lua_pushstring(luastate, "type");
        lua_pushstring(luastate, record);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "ttl");
        lua_pushinteger(luastate, answer->ttl);
        lua_settable(luastate, -3);

        {
            uint8_t *ptr = (uint8_t *)((uint8_t *)answer + sizeof(DNSAnswerEntry));
            lua_pushstring(luastate, "rrname");
            LuaPushStringBuffer(luastate, ptr, answer->fqdn_len);
            lua_settable(luastate, -3);

            ptr = (uint8_t *)((uint8_t *)answer + sizeof(DNSAnswerEntry) + answer->fqdn_len);
            if (answer->type == DNS_RECORD_TYPE_A) {
                char a[16] = "";
                PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
                lua_pushstring(luastate, "addr");
                LuaPushStringBuffer(luastate, (uint8_t *)a, strlen(a));
                lua_settable(luastate, -3);
            } else if (answer->type == DNS_RECORD_TYPE_AAAA) {
                char a[46];
                PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
                lua_pushstring(luastate, "addr");
                LuaPushStringBuffer(luastate, (uint8_t *)a, strlen(a));
                lua_settable(luastate, -3);
            } else if (answer->data_len == 0) {
                /* not setting 'addr' */
            } else {
                lua_pushstring(luastate, "addr");
                LuaPushStringBuffer(luastate, (uint8_t *)ptr, answer->data_len);
                lua_settable(luastate, -3);
            }
        }

        lua_settable(luastate, -3);
    }

    return 1;
}

static int DnsGetAuthorityTable(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    uint32_t u = 0;
    lua_newtable(luastate);
    DNSAnswerEntry *answer = NULL;
    TAILQ_FOREACH(answer, &tx->authority_list, next) {
        lua_pushinteger(luastate, u++);

        lua_newtable(luastate);
        char record[16] = "";
        DNSCreateTypeString(answer->type, record, sizeof(record));
        lua_pushstring(luastate, "type");
        lua_pushstring(luastate, record);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "ttl");
        lua_pushinteger(luastate, answer->ttl);
        lua_settable(luastate, -3);

        {
            char *c;
            size_t input_len;
            c = BytesToString((uint8_t *)((uint8_t *)answer + sizeof(DNSAnswerEntry)), answer->fqdn_len);
            if (c != NULL) {
                input_len = strlen(c);
                /* sanity check */
                if (input_len > (size_t)(2 * answer->fqdn_len)) {
                    SCFree(c);
                    return LuaCallbackError(luastate, "invalid length");
                }
                lua_pushstring(luastate, "rrname");
                LuaPushStringBuffer(luastate, (uint8_t *)c, input_len);
                lua_settable(luastate, -3);
                SCFree(c);
            }
        }


        lua_settable(luastate, -3);
    }

    return 1;
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
