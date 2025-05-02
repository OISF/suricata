/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "util-lua-ja3.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "app-layer-ssl.h"
#include "rust.h"

static const char ja3_tx[] = "suricata:ja3:tx";

struct LuaTx {
    void *tx; // Quic or TLS Transaction
    AppProto alproto;
};

static int LuaJa3GetTx(lua_State *L)
{
    AppProto alproto = ALPROTO_QUIC;
    if (LuaStateNeedProto(L, ALPROTO_TLS)) {
        alproto = ALPROTO_TLS;
    } else if (!(LuaStateNeedProto(L, ALPROTO_QUIC))) {
        return LuaCallbackError(L, "error: protocol nor tls neither quic");
    }
    void *tx = LuaStateGetTX(L);
    if (tx == NULL) {
        return LuaCallbackError(L, "error: no tx available");
    }
    struct LuaTx *ltx = (struct LuaTx *)lua_newuserdata(L, sizeof(*ltx));
    if (ltx == NULL) {
        return LuaCallbackError(L, "error: fail to allocate user data");
    }
    ltx->tx = tx;
    ltx->alproto = alproto;

    luaL_getmetatable(L, ja3_tx);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaJa3TxGetHash(lua_State *L)
{
    struct LuaTx *ltx = luaL_testudata(L, 1, ja3_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (ltx->alproto == ALPROTO_TLS) {
        SSLState *ssl_state = (SSLState *)ltx->tx;
        if (ssl_state->client_connp.ja3_hash == NULL) {
            lua_pushnil(L);
            return 1;
        }
        return LuaPushStringBuffer(L, (uint8_t *)ssl_state->client_connp.ja3_hash,
                strlen(ssl_state->client_connp.ja3_hash));
    } // else QUIC {
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    if (!SCQuicTxGetJa3(ltx->tx, STREAM_TOSERVER, &buf, &b_len)) {
        lua_pushnil(L);
        return 1;
    }
    uint8_t ja3_hash[SC_MD5_HEX_LEN + 1];
    // this adds a final zero
    SCMd5HashBufferToHex(buf, b_len, (char *)ja3_hash, SC_MD5_HEX_LEN + 1);
    return LuaPushStringBuffer(L, ja3_hash, SC_MD5_HEX_LEN);
}

static int LuaJa3TxGetString(lua_State *L)
{
    struct LuaTx *ltx = luaL_testudata(L, 1, ja3_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (ltx->alproto == ALPROTO_TLS) {
        SSLState *ssl_state = (SSLState *)ltx->tx;
        if (ssl_state->client_connp.ja3_str == NULL ||
                ssl_state->client_connp.ja3_str->data == NULL) {
            lua_pushnil(L);
            return 1;
        }
        return LuaPushStringBuffer(L, (uint8_t *)ssl_state->client_connp.ja3_str->data,
                ssl_state->client_connp.ja3_str->used);
    } // else QUIC {
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    if (!SCQuicTxGetJa3(ltx->tx, STREAM_TOSERVER, &buf, &b_len)) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static int LuaJa3TxGetServerHash(lua_State *L)
{
    struct LuaTx *ltx = luaL_testudata(L, 1, ja3_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (ltx->alproto == ALPROTO_TLS) {
        SSLState *ssl_state = (SSLState *)ltx->tx;
        if (ssl_state->server_connp.ja3_hash == NULL) {
            lua_pushnil(L);
            return 1;
        }
        return LuaPushStringBuffer(L, (uint8_t *)ssl_state->server_connp.ja3_hash,
                strlen(ssl_state->server_connp.ja3_hash));
    } // else QUIC {
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    if (!SCQuicTxGetJa3(ltx->tx, STREAM_TOCLIENT, &buf, &b_len)) {
        lua_pushnil(L);
        return 1;
    }
    uint8_t ja3_hash[SC_MD5_HEX_LEN + 1];
    // this adds a final zero
    SCMd5HashBufferToHex(buf, b_len, (char *)ja3_hash, SC_MD5_HEX_LEN + 1);
    return LuaPushStringBuffer(L, ja3_hash, SC_MD5_HEX_LEN);
}

static int LuaJa3TxGetServerString(lua_State *L)
{
    struct LuaTx *ltx = luaL_testudata(L, 1, ja3_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (ltx->alproto == ALPROTO_TLS) {
        SSLState *ssl_state = (SSLState *)ltx->tx;
        if (ssl_state->server_connp.ja3_str == NULL ||
                ssl_state->server_connp.ja3_str->data == NULL) {
            lua_pushnil(L);
            return 1;
        }
        return LuaPushStringBuffer(L, (uint8_t *)ssl_state->server_connp.ja3_str->data,
                ssl_state->server_connp.ja3_str->used);
    } // else QUIC {
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    if (!SCQuicTxGetJa3(ltx->tx, STREAM_TOCLIENT, &buf, &b_len)) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static const struct luaL_Reg txlib[] = {
    // clang-format off
    { "ja3_get_hash", LuaJa3TxGetHash },
    { "ja3_get_string", LuaJa3TxGetString },
    { "ja3s_get_hash", LuaJa3TxGetServerHash },
    { "ja3s_get_string", LuaJa3TxGetServerString },
    { NULL, NULL, }
    // clang-format on
};

static int LuaJa3Enable(lua_State *L)
{
    SSLEnableJA3();
    return 1;
}

static const struct luaL_Reg ja3lib[] = {
    // clang-format off
    { "get_tx", LuaJa3GetTx },
    { "enable_ja3", LuaJa3Enable },
    { NULL, NULL,},
    // clang-format on
};

int SCLuaLoadJa3Lib(lua_State *L)
{
    luaL_newmetatable(L, ja3_tx);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, txlib, 0);

    luaL_newlib(L, ja3lib);
    return 1;
}
