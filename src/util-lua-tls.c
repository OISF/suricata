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

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-tls.h"

static const char tls_state_mt[] = "suricata:tls";

struct LuaTls {
    const SSLState *state; // state
};

static int LuaTlsFlowStateGet(lua_State *luastate)
{
    if (!LuaStateNeedProto(luastate, ALPROTO_TLS)) {
        return LuaCallbackError(luastate, "error: protocol not tls");
    }
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    struct LuaTls *s = (struct LuaTls *)lua_newuserdata(luastate, sizeof(*s));
    if (s == NULL) {
        LUA_ERROR("failed to allocate userdata");
    }

    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    s->state = (const SSLState *)state;
    luaL_getmetatable(luastate, tls_state_mt);
    lua_setmetatable(luastate, -2);
    return 1;
}

static int GetCertNotBefore(lua_State *luastate, bool client, const SSLState *ssl_state)
{
    const SSLStateConnp *connp;

    if (client) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_before == 0)
        return LuaCallbackError(luastate, "error: no certificate NotBefore");

    return LuaPushInteger(luastate, connp->cert0_not_before);
}

static int LuaTlsGetServerCertNotBefore(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertNotBefore(luastate, false, s->state);
}

static int LuaTlsGetClientCertNotBefore(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertNotBefore(luastate, true, s->state);
}

static int GetCertNotAfter(lua_State *luastate, bool client, const SSLState *ssl_state)
{
    const SSLStateConnp *connp;

    if (client) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_after == 0)
        return LuaCallbackError(luastate, "error: no certificate NotAfter");

    return LuaPushInteger(luastate, connp->cert0_not_after);
}

static int LuaTlsGetServerCertNotAfter(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    return GetCertNotAfter(luastate, false, s->state);
}
static int LuaTlsGetClientCertNotAfter(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    return GetCertNotAfter(luastate, true, s->state);
}

static int GetCertInfo(lua_State *luastate, bool client, const SSLState *ssl_state)
{
    const SSLStateConnp *connp;

    if (client) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_subject == NULL)
        return LuaCallbackError(luastate, "error: no cert");

    /* tls.version */
    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(ssl_state->server_connp.version, ssl_version);

    int r = LuaPushStringBuffer(luastate, (uint8_t *)ssl_version, strlen(ssl_version));
    r += LuaPushStringBuffer(luastate, (uint8_t *)connp->cert0_subject, strlen(connp->cert0_subject));
    r += LuaPushStringBuffer(luastate, (uint8_t *)connp->cert0_issuerdn, strlen(connp->cert0_issuerdn));
    r += LuaPushStringBuffer(luastate, (uint8_t *)connp->cert0_fingerprint, strlen(connp->cert0_fingerprint));
    return r;
}

static int LuaTlsGetServerCertInfo(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    return GetCertInfo(luastate, false, s->state);
}

static int LuaTlsGetClientCertInfo(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    return GetCertInfo(luastate, true, s->state);
}

static int GetSNI(lua_State *luastate, const SSLState *ssl_state)
{
    if (ssl_state->client_connp.sni == NULL)
        return LuaCallbackError(luastate, "error: no server name indication");

    return LuaPushStringBuffer(luastate, (uint8_t *)ssl_state->client_connp.sni,
                               strlen(ssl_state->client_connp.sni));
}

static int LuaTlsGetSNI(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    return GetSNI(luastate, s->state);
}

static int GetCertChain(lua_State *luastate, bool client)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    const SSLStateConnp *connp;

    if (client) {
        connp = &s->state->client_connp;
    } else {
        connp = &s->state->server_connp;
    }

    uint32_t u = 0;
    lua_newtable(luastate);
    SSLCertsChain *cert = NULL;

    TAILQ_FOREACH(cert, &connp->certs, next)
    {
        lua_pushinteger(luastate, u++);

        lua_newtable(luastate);

        lua_pushstring(luastate, "length");
        lua_pushinteger(luastate, cert->cert_len);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "data");
        LuaPushStringBuffer(luastate, cert->cert_data, cert->cert_len);

        lua_settable(luastate, -3);
        lua_settable(luastate, -3);
    }

    return 1;
}

static int LuaTlsGetServerCertChain(lua_State *luastate)
{
    return GetCertChain(luastate, false);
}

static int LuaTlsGetClientCertChain(lua_State *luastate)
{
    return GetCertChain(luastate, true);
}

static int GetCertSerial(lua_State *luastate, bool client)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get flow");
    }

    const SSLStateConnp *connp;

    if (client) {
        connp = &s->state->client_connp;
    } else {
        connp = &s->state->server_connp;
    }
    if (connp->cert0_serial == NULL)
        return LuaCallbackError(luastate, "error: no certificate serial");

    return LuaPushStringBuffer(
            luastate, (uint8_t *)connp->cert0_serial, strlen(connp->cert0_serial));
}

static int LuaTlsGetServerCertSerial(lua_State *luastate)
{
    return GetCertSerial(luastate, false);
}

static int LuaTlsGetClientCertSerial(lua_State *luastate)
{
    return GetCertSerial(luastate, true);
}

static int GetAgreedVersion(lua_State *luastate, bool client)
{
    struct LuaTls *s = (struct LuaTls *)luaL_checkudata(luastate, 1, tls_state_mt);
    if (s->state == NULL) {
        LUA_ERROR("failed to get state");
    }

    uint16_t version;
    if (client) {
        version = s->state->client_connp.version;
    } else {
        version = s->state->server_connp.version;
    }

    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(version, ssl_version);

    lua_pushstring(luastate, (const char *)&ssl_version);
    return 1;
}

static int LuaTlsGetServerVersion(lua_State *luastate)
{
    return GetAgreedVersion(luastate, false);
}

static int LuaTlsGetClientVersion(lua_State *luastate)
{
    return GetAgreedVersion(luastate, true);
}

static const struct luaL_Reg tlslib_meta[] = {
    // clang-format off
    { "get_server_cert_not_before", LuaTlsGetServerCertNotBefore },
    { "get_client_cert_not_before", LuaTlsGetClientCertNotBefore },
    { "get_server_cert_not_after", LuaTlsGetServerCertNotAfter },
    { "get_client_cert_not_after", LuaTlsGetClientCertNotAfter },
    { "get_server_version", LuaTlsGetServerVersion },
    { "get_client_version", LuaTlsGetClientVersion },
    { "get_server_serial", LuaTlsGetServerCertSerial },
    { "get_client_serial", LuaTlsGetClientCertSerial },
    { "get_server_cert_info", LuaTlsGetServerCertInfo },
    { "get_client_cert_info", LuaTlsGetClientCertInfo },
    { "get_client_sni", LuaTlsGetSNI },
    { "get_client_cert_chain", LuaTlsGetClientCertChain },
    { "get_server_cert_chain", LuaTlsGetServerCertChain },
    { NULL, NULL, }
    // clang-format off
};

static const struct luaL_Reg tlslib[] = {
    // clang-format off
    { "get_tx", LuaTlsFlowStateGet },
    { NULL, NULL, },
    // clang-format on
};

int SCLuaLoadTlsLib(lua_State *L)
{
    luaL_newmetatable(L, tls_state_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, tlslib_meta, 0);

    luaL_newlib(L, tlslib);
    return 1;
}
