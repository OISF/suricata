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
#include "util-lua-dns.h"

#ifdef HAVE_RUST
#include "rust-dns-dns-gen.h"
#endif

static int DnsGetDnsRrname(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
#ifdef HAVE_RUST
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    for (uint16_t i = 0;; i++) {
        uint32_t buf_len;
        uint8_t *buf;

        if (!rs_dns_tx_get_query_name(tx, i, &buf, &buf_len)) {
            break;
        }
        
        char *rrname = BytesToString(buf, buf_len);
        if (rrname != NULL) {
            size_t input_len = strlen(rrname);
            /* sanity check */
            if (input_len > (size_t)(2 * buf_len)) {
                SCFree(rrname);
                return LuaCallbackError(luastate, "invalid length");
            }
            int ret = LuaPushStringBuffer(luastate, (uint8_t *)rrname,
                input_len);
            SCFree(rrname);
            return ret;
        }
    }
#else
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
#endif
    return LuaCallbackError(luastate, "no query");
}

static int DnsGetTxid(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
#ifdef HAVE_RUST
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");
    uint16_t tx_id = rs_dns_tx_get_tx_id(tx);
    lua_pushinteger(luastate, tx_id);
#else
    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    lua_pushinteger(luastate, tx->tx_id);
#endif
    return 1;
}

static int DnsGetRcode(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
    uint16_t rcode = 0;
#ifdef HAVE_RUST
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "internal error: no tx");
    }
    uint16_t flags = rs_dns_tx_get_response_flags(tx);
    rcode = flags & 0x000f;
#else
    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");
    rcode = tx->rcode;
#endif
    if (rcode) {
        char rcode_str[16] = "";
        DNSCreateRcodeString(rcode, rcode_str, sizeof(rcode_str));
        return LuaPushStringBuffer(luastate, (const uint8_t *)rcode_str, strlen(rcode_str));
    } else {
        return 0;
    }
}

static int DnsGetRecursionDesired(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");
#ifdef HAVE_RUST
    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    uint16_t flags = rs_dns_tx_get_response_flags(tx);
    int recursion_desired = flags & 0x0080 ? 1 : 0;

    lua_pushboolean(luastate, recursion_desired);
#else
    DNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    lua_pushboolean(luastate, tx->recursion_desired);
#endif
    return 1;
}

static int DnsGetQueryTable(lua_State *luastate)
{
#ifdef HAVE_RUST
    if (!(LuaStateNeedProto(luastate, ALPROTO_DNS)))
        return LuaCallbackError(luastate, "error: protocol not dns");

    RSDNSTransaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    lua_newtable(luastate);

    uint8_t *name;
    uint32_t name_len;

    for (uint16_t i = 0;; i++) {

        if (!rs_dns_tx_get_query_name(tx, i, &name, &name_len)) {
            break;
        }

        lua_pushinteger(luastate, i);
        lua_newtable(luastate);

        uint16_t rrtype;
        if (rs_dns_tx_get_query_rrtype(tx, i, &rrtype)) {
            char s_rrtype[16] = "";
            DNSCreateTypeString(rrtype, s_rrtype, sizeof(s_rrtype));
            lua_pushstring(luastate, "type");
            lua_pushstring(luastate, s_rrtype);
            lua_settable(luastate, -3);
        }

        char *s = BytesToString(name, name_len);
        if (s != NULL) {
            size_t slen = strlen(s);
            if (slen > name_len * 2) {
                SCFree(s);
                return LuaCallbackError(luastate, "invalid length");
            }
            lua_pushstring(luastate, "rrname");
            LuaPushStringBuffer(luastate, (uint8_t *)s, slen);
            lua_settable(luastate, -3);
            SCFree(s);
        }

        lua_pushinteger(luastate, i++);

    }

    return 1;
#else
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
#endif
}

static int DnsGetAnswerTable(lua_State *luastate)
{
#ifdef HAVE_RUST
    SCLogNotice("DnsGetAnswerTable not implemented for Rust DNS.");
    return 1;
#else
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
                if (answer->data_len == 4) {
                    PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
                }
                lua_pushstring(luastate, "addr");
                LuaPushStringBuffer(luastate, (uint8_t *)a, strlen(a));
                lua_settable(luastate, -3);
            } else if (answer->type == DNS_RECORD_TYPE_AAAA) {
                char a[46] = "";
                if (answer->data_len == 16) {
                    PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
                }
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
#endif
}

static int DnsGetAuthorityTable(lua_State *luastate)
{
#ifdef HAVE_RUST
    SCLogNotice("DnsGetAuthorityTable not implemented for Rust DNS");
    return 1;
#else
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
#endif
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
