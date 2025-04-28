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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "util-lua-ssh.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "rust.h"

// #define SSH_MT "suricata:ssh:tx"
static const char ssh_tx[] = "suricata:ssh:tx";

struct LuaTx {
    void *tx; // SSHTransaction
};

static int LuaSshGetTx(lua_State *L)
{
    if (!(LuaStateNeedProto(L, ALPROTO_SSH))) {
        return LuaCallbackError(L, "error: protocol not ssh");
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

    luaL_getmetatable(L, ssh_tx);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaSshTxGetProto(lua_State *L, uint8_t flags)
{
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    struct LuaTx *ltx = luaL_testudata(L, 1, ssh_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (SCSshTxGetProtocol(ltx->tx, &buf, &b_len, flags) != 1) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static int LuaSshTxGetServerProto(lua_State *L)
{
    return LuaSshTxGetProto(L, STREAM_TOCLIENT);
}

static int LuaSshTxGetClientProto(lua_State *L)
{
    return LuaSshTxGetProto(L, STREAM_TOSERVER);
}

static int LuaSshTxGetSoftware(lua_State *L, uint8_t flags)
{
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    struct LuaTx *ltx = luaL_testudata(L, 1, ssh_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (SCSshTxGetSoftware(ltx->tx, &buf, &b_len, flags) != 1) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static int LuaSshTxGetServerSoftware(lua_State *L)
{
    return LuaSshTxGetSoftware(L, STREAM_TOCLIENT);
}

static int LuaSshTxGetClientSoftware(lua_State *L)
{
    return LuaSshTxGetSoftware(L, STREAM_TOSERVER);
}

static int LuaSshTxGetHassh(lua_State *L, uint8_t flags)
{
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    struct LuaTx *ltx = luaL_testudata(L, 1, ssh_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (SCSshTxGetHassh(ltx->tx, &buf, &b_len, flags) != 1) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static int LuaSshTxGetClientHassh(lua_State *L)
{
    return LuaSshTxGetHassh(L, STREAM_TOSERVER);
}

static int LuaSshTxGetServerHassh(lua_State *L)
{
    return LuaSshTxGetHassh(L, STREAM_TOCLIENT);
}

static int LuaSshTxGetHasshString(lua_State *L, uint8_t flags)
{
    const uint8_t *buf = NULL;
    uint32_t b_len = 0;
    struct LuaTx *ltx = luaL_testudata(L, 1, ssh_tx);
    if (ltx == NULL) {
        lua_pushnil(L);
        return 1;
    }
    if (SCSshTxGetHasshString(ltx->tx, &buf, &b_len, flags) != 1) {
        lua_pushnil(L);
        return 1;
    }
    return LuaPushStringBuffer(L, buf, b_len);
}

static int LuaSshTxGetClientHasshString(lua_State *L)
{
    return LuaSshTxGetHasshString(L, STREAM_TOSERVER);
}

static int LuaSshTxGetServerHasshString(lua_State *L)
{
    return LuaSshTxGetHasshString(L, STREAM_TOCLIENT);
}

static const struct luaL_Reg txlib[] = {
    // clang-format off
    { "server_proto", LuaSshTxGetServerProto },
    { "server_software", LuaSshTxGetServerSoftware },
    { "client_proto", LuaSshTxGetClientProto },
    { "client_software", LuaSshTxGetClientSoftware },
    { "client_hassh", LuaSshTxGetClientHassh },
    { "server_hassh", LuaSshTxGetServerHassh },
    { "client_hassh_string", LuaSshTxGetClientHasshString },
    { "server_hassh_string", LuaSshTxGetServerHasshString },
    { NULL, NULL, }
    // clang-format on
};

static int LuaSshEnableHassh(lua_State *L)
{
    SCSshEnableHassh();
    return 1;
}

static const struct luaL_Reg sshlib[] = {
    // clang-format off
    { "get_tx", LuaSshGetTx },
    { "enable_hassh", LuaSshEnableHassh },
    { NULL, NULL,},
    // clang-format on
};

int SCLuaLoadSshLib(lua_State *L)
{
    luaL_newmetatable(L, ssh_tx);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, txlib, 0);

    luaL_newlib(L, sshlib);
    return 1;
}
