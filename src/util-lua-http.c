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
 *
 */

#include "suricata-common.h"

#ifdef HAVE_LUA
#include "util-time.h"
#include "util-logopenfile.h"
#include "util-proto-name.h"
#include "util-buffer.h"
#include "util-privs.h"
#include "app-layer-parser.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "output.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-print.h"
#include "tm-threads.h"
#include "threadvars.h"
#include "threads.h"
#include "conf.h"
#include "pkt-var.h"
#include "detect.h"
#endif
#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-http.h"

static int HttpGetRequestHost(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (tx->request_hostname == NULL)
        return LuaCallbackError(luastate, "no request hostname");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(tx->request_hostname), bstr_len(tx->request_hostname));
}

static int HttpGetRequestUriRaw(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (tx->request_uri == NULL)
        return LuaCallbackError(luastate, "no request uri");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
}

static int HttpGetRequestUriNormalized(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (htud == NULL)
        return LuaCallbackError(luastate, "no htud in tx");

    if (htud->request_uri_normalized == NULL ||
        bstr_ptr(htud->request_uri_normalized) == NULL ||
        bstr_len(htud->request_uri_normalized) == 0)
        return LuaCallbackError(luastate, "no normalized uri");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(htud->request_uri_normalized),
            bstr_len(htud->request_uri_normalized));
}

static int HttpGetRequestLine(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (tx->request_line == NULL)
        return LuaCallbackError(luastate, "no request_line");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(tx->request_line), bstr_len(tx->request_line));
}

static int HttpGetResponseLine(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (tx->response_line == NULL)
        return LuaCallbackError(luastate, "no response_line");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(tx->response_line), bstr_len(tx->response_line));
}

static int HttpGetHeader(lua_State *luastate, int dir)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    const char *name = LuaGetStringArgument(luastate, 1);
    if (name == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");

    htp_table_t *headers = tx->request_headers;
    if (dir == 1)
        headers = tx->response_headers;
    if (headers == NULL)
        return LuaCallbackError(luastate, "tx has no headers");

    htp_header_t *h = (htp_header_t *)htp_table_get_c(headers, name);
    if (h == NULL || bstr_len(h->value) == 0)
        return LuaCallbackError(luastate, "header not found");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(h->value), bstr_len(h->value));
}

static int HttpGetRequestHeader(lua_State *luastate)
{
    return HttpGetHeader(luastate, 0 /* request */);
}

static int HttpGetResponseHeader(lua_State *luastate)
{
    return HttpGetHeader(luastate, 1 /* response */);
}

static int HttpGetRawHeaders(lua_State *luastate, int dir)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (htud == NULL)
        return LuaCallbackError(luastate, "no htud in tx");

    uint8_t *raw = htud->request_headers_raw;
    uint32_t raw_len = htud->request_headers_raw_len;
    if (dir == 1) {
        raw = htud->response_headers_raw;
        raw_len = htud->response_headers_raw_len;
    }

    if (raw == NULL || raw_len == 0)
        return LuaCallbackError(luastate, "no raw headers");

    return LuaPushStringBuffer(luastate, raw, raw_len);
}

static int HttpGetRawRequestHeaders(lua_State *luastate)
{
    return HttpGetRawHeaders(luastate, 0);
}

static int HttpGetRawResponseHeaders(lua_State *luastate)
{
    return HttpGetRawHeaders(luastate, 1);
}


static int HttpGetHeaders(lua_State *luastate, int dir)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    htp_table_t *table = tx->request_headers;
    if (dir == 1)
        table = tx->response_headers;
    if (tx->request_headers == NULL)
        return LuaCallbackError(luastate, "no headers");

    lua_newtable(luastate);
    htp_header_t *h = NULL;
    size_t i = 0;
    size_t no_of_headers = htp_table_size(table);
    for (; i < no_of_headers; i++) {
        h = htp_table_get_index(table, i, NULL);
        LuaPushStringBuffer(luastate, bstr_ptr(h->name), bstr_len(h->name));
        LuaPushStringBuffer(luastate, bstr_ptr(h->value), bstr_len(h->value));
        lua_settable(luastate, -3);
    }
    return 1;
}

/** \brief return request headers as lua table */
static int HttpGetRequestHeaders(lua_State *luastate)
{
    return HttpGetHeaders(luastate, 0);
}

/** \brief return response headers as lua table */
static int HttpGetResponseHeaders(lua_State *luastate)
{
    return HttpGetHeaders(luastate, 1);
}

static int HttpGetBody(lua_State *luastate, int dir)
{
    HtpBody *body = NULL;

    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (htud == NULL)
        return LuaCallbackError(luastate, "no htud in tx");

    if (dir == 0)
        body = &htud->request_body;
    else
        body = &htud->response_body;

    if (body->first == NULL)
        return LuaCallbackError(luastate, "no body");

    int index = 1;
    HtpBodyChunk *chunk = body->first;
    lua_newtable(luastate);
    while (chunk != NULL) {
        lua_pushinteger(luastate, index);

        const uint8_t *data = NULL;
        uint32_t data_len = 0;
        StreamingBufferSegmentGetData(body->sb, &chunk->sbseg, &data, &data_len);
        LuaPushStringBuffer(luastate, data, data_len);

        lua_settable(luastate, -3);

        chunk = chunk->next;
        index++;
    }

    if (body->first && body->last) {
        lua_pushinteger(luastate, body->first->sbseg.stream_offset);
        lua_pushinteger(luastate, body->last->sbseg.stream_offset + body->last->sbseg.segment_len);
        return 3;
    } else {
        return 1;
    }
}

static int HttpGetRequestBody(lua_State *luastate)
{
    return HttpGetBody(luastate, 0);
}

static int HttpGetResponseBody(lua_State *luastate)
{
    return HttpGetBody(luastate, 1);
}

/** \brief register http lua extensions in a luastate */
int LuaRegisterHttpFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, HttpGetRequestHeader);
    lua_setglobal(luastate, "HttpGetRequestHeader");
    lua_pushcfunction(luastate, HttpGetResponseHeader);
    lua_setglobal(luastate, "HttpGetResponseHeader");
    lua_pushcfunction(luastate, HttpGetRequestLine);
    lua_setglobal(luastate, "HttpGetRequestLine");
    lua_pushcfunction(luastate, HttpGetResponseLine);
    lua_setglobal(luastate, "HttpGetResponseLine");
    lua_pushcfunction(luastate, HttpGetRawRequestHeaders);
    lua_setglobal(luastate, "HttpGetRawRequestHeaders");
    lua_pushcfunction(luastate, HttpGetRawResponseHeaders);
    lua_setglobal(luastate, "HttpGetRawResponseHeaders");
    lua_pushcfunction(luastate, HttpGetRequestUriRaw);
    lua_setglobal(luastate, "HttpGetRequestUriRaw");
    lua_pushcfunction(luastate, HttpGetRequestUriNormalized);
    lua_setglobal(luastate, "HttpGetRequestUriNormalized");
    lua_pushcfunction(luastate, HttpGetRequestHeaders);
    lua_setglobal(luastate, "HttpGetRequestHeaders");
    lua_pushcfunction(luastate, HttpGetResponseHeaders);
    lua_setglobal(luastate, "HttpGetResponseHeaders");
    lua_pushcfunction(luastate, HttpGetRequestHost);
    lua_setglobal(luastate, "HttpGetRequestHost");

    lua_pushcfunction(luastate, HttpGetRequestBody);
    lua_setglobal(luastate, "HttpGetRequestBody");
    lua_pushcfunction(luastate, HttpGetResponseBody);
    lua_setglobal(luastate, "HttpGetResponseBody");
    return 0;
}

#endif /* HAVE_LUA */
