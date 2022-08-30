/* Copyright (C) 2017-2022 Open Information Security Foundation
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
#include "app-layer-ssl.h"
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
#include "util-lua-ja3.h"

static int Ja3GetHash(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol is not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->client_connp.ja3_hash == NULL)
        return LuaCallbackError(luastate, "error: no JA3 hash");

    return LuaPushStringBuffer(luastate,
                               (uint8_t *)ssl_state->client_connp.ja3_hash,
                               strlen(ssl_state->client_connp.ja3_hash));
}

static int Ja3GetString(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol is not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->client_connp.ja3_str == NULL ||
            ssl_state->client_connp.ja3_str->data == NULL)
        return LuaCallbackError(luastate, "error: no JA3 str");

    return LuaPushStringBuffer(luastate,
                               (uint8_t *)ssl_state->client_connp.ja3_str->data,
                               ssl_state->client_connp.ja3_str->used);
}

static int Ja3SGetHash(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol is not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->server_connp.ja3_hash == NULL)
        return LuaCallbackError(luastate, "error: no JA3S hash");

    return LuaPushStringBuffer(luastate,
                               (uint8_t *)ssl_state->server_connp.ja3_hash,
                               strlen(ssl_state->server_connp.ja3_hash));
}

static int Ja3SGetString(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol is not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->server_connp.ja3_str == NULL ||
            ssl_state->server_connp.ja3_str->data == NULL)
        return LuaCallbackError(luastate, "error: no JA3S str");

    return LuaPushStringBuffer(luastate,
                               (uint8_t *)ssl_state->server_connp.ja3_str->data,
                               ssl_state->server_connp.ja3_str->used);
}

/** *\brief Register JA3 Lua extensions */
int LuaRegisterJa3Functions(lua_State *luastate)
{
    lua_pushcfunction(luastate, Ja3GetHash);
    lua_setglobal(luastate, "Ja3GetHash");

    lua_pushcfunction(luastate, Ja3GetString);
    lua_setglobal(luastate, "Ja3GetString");

    lua_pushcfunction(luastate, Ja3SGetHash);
    lua_setglobal(luastate, "Ja3SGetHash");

    lua_pushcfunction(luastate, Ja3SGetString);
    lua_setglobal(luastate, "Ja3SGetString");

    return 0;
}

#endif /* HAVE_LUA */
