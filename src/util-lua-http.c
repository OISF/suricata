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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "app-layer-htp.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-http.h"

static const char htp_tx[] = "suricata:http:tx";

struct LuaTx {
    htp_tx_t *tx;
};

static int LuaHttpGetTx(lua_State *luastate)
{
    if (!LuaStateNeedProto(luastate, ALPROTO_HTTP1)) {
        return LuaCallbackError(luastate, "error: protocol not http");
    }

    htp_tx_t *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "error: no tx available");
    }
    struct LuaTx *ltx = (struct LuaTx *)lua_newuserdata(luastate, sizeof(*ltx));
    if (ltx == NULL) {
        return LuaCallbackError(luastate, "error: failed to allocate user data");
    }

    ltx->tx = tx;

    luaL_getmetatable(luastate, htp_tx);
    lua_setmetatable(luastate, -2);

    return 1;
}

static int LuaHttpGetRequestHost(lua_State *luastate)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    const struct bstr *host = htp_tx_request_hostname(tx->tx);
    if (host == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    return LuaPushStringBuffer(luastate, bstr_ptr(host), bstr_len(host));
}

static int LuaHttpGetRequestUriRaw(lua_State *luastate)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    const struct bstr *uri = htp_tx_request_uri(tx->tx);
    if (uri == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    return LuaPushStringBuffer(luastate, bstr_ptr(uri), bstr_len(uri));
}

static int LuaHttpGetRequestUriNormalized(lua_State *luastate)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx->tx);

    if (request_uri_normalized == NULL || bstr_ptr(request_uri_normalized) == NULL ||
            bstr_len(request_uri_normalized) == 0)
        return LuaCallbackError(luastate, "no normalized uri");

    return LuaPushStringBuffer(
            luastate, bstr_ptr(request_uri_normalized), bstr_len(request_uri_normalized));
}

static int LuaHttpGetRequestLine(lua_State *luastate)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    const struct bstr *line = htp_tx_request_line(tx->tx);
    if (line == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    return LuaPushStringBuffer(luastate, bstr_ptr(line), bstr_len(line));
}

static int LuaHttpGetResponseLine(lua_State *luastate)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    const struct bstr *line = htp_tx_response_line(tx->tx);
    if (line == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    return LuaPushStringBuffer(luastate, bstr_ptr(line), bstr_len(line));
}

static int LuaHttpGetHeader(lua_State *luastate, int dir)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    /* since arg was added at last, it must be on top of the stack */
    const char *name = LuaGetStringArgument(luastate, lua_gettop(luastate));
    if (name == NULL) {
        return LuaCallbackError(luastate, "argument missing, empty or wrong type");
    }

    const htp_header_t *h = NULL;
    if (dir == 0) {
        h = htp_tx_request_header(tx->tx, name);
    } else {
        h = htp_tx_response_header(tx->tx, name);
    }

    if (h == NULL || htp_header_value_len(h) == 0) {
        return LuaCallbackError(luastate, "header not found");
    }

    return LuaPushStringBuffer(luastate, htp_header_value_ptr(h), htp_header_value_len(h));
}

static int LuaHttpGetRequestHeader(lua_State *luastate)
{
    return LuaHttpGetHeader(luastate, 0 /* request */);
}

static int LuaHttpGetResponseHeader(lua_State *luastate)
{
    return LuaHttpGetHeader(luastate, 1 /* response */);
}

static int LuaHttpGetRawHeaders(lua_State *luastate, int dir)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx->tx);

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

static int LuaHttpGetRawRequestHeaders(lua_State *luastate)
{
    return LuaHttpGetRawHeaders(luastate, 0);
}

static int LuaHttpGetRawResponseHeaders(lua_State *luastate)
{
    return LuaHttpGetRawHeaders(luastate, 1);
}

static int LuaHttpGetHeaders(lua_State *luastate, int dir)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    const htp_headers_t *table = htp_tx_request_headers(tx->tx);
    if (dir == 1)
        table = htp_tx_response_headers(tx->tx);
    if (table == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

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
static int LuaHttpGetRequestHeaders(lua_State *luastate)
{
    return LuaHttpGetHeaders(luastate, 0);
}

/** \brief return response headers as lua table */
static int LuaHttpGetResponseHeaders(lua_State *luastate)
{
    return LuaHttpGetHeaders(luastate, 1);
}

static int LuaHttpGetBody(lua_State *luastate, int dir)
{
    struct LuaTx *tx = luaL_testudata(luastate, 1, htp_tx);
    if (tx == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx->tx);

    HtpBody *body = NULL;
    if (dir == 0)
        body = &htud->request_body;
    else
        body = &htud->response_body;

    if (body->first == NULL) {
        return LuaCallbackError(luastate, "no body found");
    }

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

static int LuaHttpGetRequestBody(lua_State *luastate)
{
    return LuaHttpGetBody(luastate, 0);
}

static int LuaHttpGetResponseBody(lua_State *luastate)
{
    return LuaHttpGetBody(luastate, 1);
}

static const struct luaL_Reg txlib[] = {
    // clang-format off
    {"request_header", LuaHttpGetRequestHeader},
    {"response_header", LuaHttpGetResponseHeader},
    {"request_line", LuaHttpGetRequestLine},
    {"response_line", LuaHttpGetResponseLine},
    {"request_headers_raw", LuaHttpGetRawRequestHeaders},
    {"response_headers_raw", LuaHttpGetRawResponseHeaders},
    {"request_uri_raw", LuaHttpGetRequestUriRaw},
    {"request_uri_normalized", LuaHttpGetRequestUriNormalized},
    {"request_headers", LuaHttpGetRequestHeaders},
    {"response_headers", LuaHttpGetResponseHeaders},
    {"request_host", LuaHttpGetRequestHost},
    {"request_body", LuaHttpGetRequestBody},
    {"response_body", LuaHttpGetResponseBody},
    {NULL, NULL,},
    // clang-format on
};

static const struct luaL_Reg htplib[] = {
    // clang-format off
    {"get_tx", LuaHttpGetTx },
    {NULL, NULL,},
    // clang-format on
};

int SCLuaLoadHttpLib(lua_State *luastate)
{
    luaL_newmetatable(luastate, htp_tx);
    lua_pushvalue(luastate, -1);
    lua_setfield(luastate, -2, "__index");
    luaL_setfuncs(luastate, txlib, 0);
    luaL_newlib(luastate, htplib);
    return 1;
}
