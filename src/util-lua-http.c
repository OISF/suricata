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
#include "app-layer-htp.h"
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
#include "util-lua-http.h"

static int HttpGetRequestHost(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (htp_tx_request_hostname(tx) == NULL)
        return LuaCallbackError(luastate, "no request hostname");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(htp_tx_request_hostname(tx)), bstr_len(htp_tx_request_hostname(tx)));
}

static int HttpGetRequestUriRaw(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (htp_tx_request_uri(tx) == NULL)
        return LuaCallbackError(luastate, "no request uri");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(htp_tx_request_uri(tx)), bstr_len(htp_tx_request_uri(tx)));
}

static int HttpGetRequestUriNormalized(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    HtpState *htp_state = htp_connp_user_data(htp_tx_connp(tx));
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx, htp_state->cfg->uri_include_all);

    if (request_uri_normalized == NULL ||
        bstr_ptr(request_uri_normalized) == NULL ||
        bstr_len(request_uri_normalized) == 0)
        return LuaCallbackError(luastate, "no normalized uri");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(request_uri_normalized),
            bstr_len(request_uri_normalized));
}

static int HttpGetRequestLine(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (htp_tx_request_line(tx) == NULL)
        return LuaCallbackError(luastate, "no request_line");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(htp_tx_request_line(tx)), bstr_len(htp_tx_request_line(tx)));
}

static int HttpGetResponseLine(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_HTTP1)))
        return LuaCallbackError(luastate, "error: protocol not http");

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL)
        return LuaCallbackError(luastate, "internal error: no tx");

    if (htp_tx_response_line(tx) == NULL)
        return LuaCallbackError(luastate, "no response_line");

    return LuaPushStringBuffer(luastate,
            bstr_ptr(htp_tx_response_line(tx)), bstr_len(htp_tx_response_line(tx)));
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

    const htp_header_t *h = NULL;
    if (dir == 0) {
        h = htp_tx_request_header(tx, name);
    } else {
        h = htp_tx_response_header(tx, name);
    }

    if (h == NULL || htp_header_value_len(h) == 0)
        return LuaCallbackError(luastate, "header not found");

    return LuaPushStringBuffer(luastate,
            htp_header_value_ptr(h), htp_header_value_len(h));
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

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_user_data(tx);
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

    const htp_table_t *table = htp_tx_request_headers(tx);
    if (dir == 1)
        table = htp_tx_response_headers(tx);
    if (htp_tx_request_headers(tx) == NULL)
        return LuaCallbackError(luastate, "no headers");

    lua_newtable(luastate);
    const htp_header_t *h = NULL;
    size_t i = 0;
    size_t no_of_headers = htp_headers_size(table);
    for (; i < no_of_headers; i++) {
        h = htp_headers_get_index(table, i);
        LuaPushStringBuffer(luastate, htp_header_name_ptr(h), htp_header_name_len(h));
        LuaPushStringBuffer(luastate, htp_header_value_ptr(h), htp_header_value_len(h));
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

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_user_data(tx);
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
