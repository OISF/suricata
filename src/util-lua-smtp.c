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
 *  \file
 *
 *  \author casec Bachelors group
 *  \author Lauritz Prag Sømme <lauritz24@me.com>
 *  \author Levi Tobiassen <levi.tobiassen@gmail.com>
 *  \author Stian Hoel Bergseth <stian.bergseth@hig.no>
 *  \author Vinjar Hillestad <vinjar.hillestad@hig.no>
 */

#include "suricata-common.h"
#include "app-layer-smtp.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-smtp.h"

#include "lua.h"
#include "lauxlib.h"

static const char smtp_tx_mt[] = "suricata:smtp:tx";

struct LuaSmtpTx {
    SMTPTransaction *tx;
};

static int LuaSmtpGetTx(lua_State *L)
{
    if (!(LuaStateNeedProto(L, ALPROTO_SMTP))) {
        return LuaCallbackError(L, "error: protocol not SMTP");
    }

    Flow *flow = LuaStateGetFlow(L);
    if (flow == NULL) {
        return LuaCallbackError(L, "error: no flow found");
    }

    SMTPState *state = (SMTPState *)FlowGetAppState(flow);
    if (state == NULL) {
        return LuaCallbackError(L, "error: no SMTP state");
    }

    SMTPTransaction *tx = state->curr_tx;
    if (tx == NULL) {
        return LuaCallbackError(L, "error: no SMTP transaction found");
    }

    struct LuaSmtpTx *lua_tx = (struct LuaSmtpTx *)lua_newuserdata(L, sizeof(*lua_tx));
    if (lua_tx == NULL) {
        return LuaCallbackError(L, "error: fail to allocate user data");
    }
    lua_tx->tx = tx;

    luaL_getmetatable(L, smtp_tx_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaSmtpTxGetMimeField(lua_State *L)
{
    struct LuaSmtpTx *tx = luaL_checkudata(L, 1, smtp_tx_mt);

    if (tx->tx->mime_state == NULL) {
        return LuaCallbackError(L, "no mime state");
    }

    const char *name = luaL_checkstring(L, 2);
    if (name == NULL) {
        return LuaCallbackError(L, "2nd argument missing, empty or wrong type");
    }

    const uint8_t *field_value;
    uint32_t field_len;
    if (SCMimeSmtpGetHeader(tx->tx->mime_state, name, &field_value, &field_len)) {
        return LuaPushStringBuffer(L, field_value, field_len);
    }

    return LuaCallbackError(L, "request mime field not found");
}

static int LuaSmtpTxGetMimeList(lua_State *L)
{
    struct LuaSmtpTx *tx = luaL_checkudata(L, 1, smtp_tx_mt);

    if (tx->tx->mime_state == NULL) {
        return LuaCallbackError(L, "no mime state");
    }

    const uint8_t *field_name;
    uint32_t field_len;
    int num = 1;
    lua_newtable(L);
    while (SCMimeSmtpGetHeaderName(tx->tx->mime_state, &field_name, &field_len, (uint32_t)num)) {
        if (field_len != 0) {
            lua_pushinteger(L, num++);
            LuaPushStringBuffer(L, field_name, field_len);
            lua_settable(L, -3);
        }
    }
    return 1;
}

static int LuaSmtpTxGetMailFrom(lua_State *L)
{
    struct LuaSmtpTx *tx = luaL_checkudata(L, 1, smtp_tx_mt);

    if (tx->tx->mail_from == NULL || tx->tx->mail_from_len == 0) {
        lua_pushnil(L);
        return 1;
    }

    return LuaPushStringBuffer(L, tx->tx->mail_from, tx->tx->mail_from_len);
}

static int LuaSmtpTxGetRcptList(lua_State *L)
{
    struct LuaSmtpTx *tx = luaL_checkudata(L, 1, smtp_tx_mt);

    /* Create a new table in luastate for rcpt list */
    lua_newtable(L);
    /* rcpt var for iterator */
    int u = 1;
    SMTPString *rcpt;

    TAILQ_FOREACH (rcpt, &tx->tx->rcpt_to_list, next) {
        lua_pushinteger(L, u++);
        LuaPushStringBuffer(L, rcpt->str, rcpt->len);
        lua_settable(L, -3);
    }

    return 1;
}

static const struct luaL_Reg smtptxlib[] = {
    { "get_mime_field", LuaSmtpTxGetMimeField },
    { "get_mime_list", LuaSmtpTxGetMimeList },
    { "get_mail_from", LuaSmtpTxGetMailFrom },
    { "get_rcpt_list", LuaSmtpTxGetRcptList },
    { NULL, NULL },
};

static const struct luaL_Reg smtplib[] = {
    { "get_tx", LuaSmtpGetTx },
    { NULL, NULL },
};

int SCLuaLoadSmtpLib(lua_State *L)
{
    luaL_newmetatable(L, smtp_tx_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, smtptxlib, 0);

    luaL_newlib(L, smtplib);
    return 1;
}
