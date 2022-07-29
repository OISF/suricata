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

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "app-layer-ssl.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-tls.h"

static int GetCertNotBefore(lua_State *luastate, const Flow *f, int direction)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_before == 0)
        return LuaCallbackError(luastate, "error: no certificate NotBefore");

    int r = LuaPushInteger(luastate, connp->cert0_not_before);

    return r;
}

static int TlsGetCertNotBefore(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    int direction = LuaStateGetDirection(luastate);

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetCertNotBefore(luastate, f, direction);

    return r;
}

static int GetCertNotAfter(lua_State *luastate, const Flow *f, int direction)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_after == 0)
        return LuaCallbackError(luastate, "error: no certificate NotAfter");

    int r = LuaPushInteger(luastate, connp->cert0_not_after);

    return r;
}

static int TlsGetCertNotAfter(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    int direction = LuaStateGetDirection(luastate);

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetCertNotAfter(luastate, f, direction);

    return r;
}

static int GetCertInfo(lua_State *luastate, const Flow *f, int direction)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    if (direction) {
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

static int TlsGetCertInfo(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    int direction = LuaStateGetDirection(luastate);

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetCertInfo(luastate, f, direction);

    return r;
}

static int GetAgreedVersion(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(ssl_state->server_connp.version, ssl_version);

    return LuaPushStringBuffer(luastate, (uint8_t *)ssl_version,
                               strlen(ssl_version));
}

static int TlsGetVersion(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetAgreedVersion(luastate, f);

    return r;
}

static int GetSNI(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->client_connp.sni == NULL)
        return LuaCallbackError(luastate, "error: no server name indication");

    return LuaPushStringBuffer(luastate, (uint8_t *)ssl_state->client_connp.sni,
                               strlen(ssl_state->client_connp.sni));
}

static int TlsGetSNI(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetSNI(luastate, f);

    return r;
}

static int GetCertSerial(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    if (ssl_state->server_connp.cert0_serial == NULL)
        return LuaCallbackError(luastate, "error: no certificate serial");

    return LuaPushStringBuffer(luastate,
                               (uint8_t *)ssl_state->server_connp.cert0_serial,
                               strlen(ssl_state->server_connp.cert0_serial));
}

static int TlsGetCertSerial(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetCertSerial(luastate, f);

    return r;
}

static int GetCertChain(lua_State *luastate, const Flow *f, int direction)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
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

static int TlsGetCertChain(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    int direction = LuaStateGetDirection(luastate);

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetCertChain(luastate, f, direction);

    return r;
}

/** \brief register tls lua extensions in a luastate */
int LuaRegisterTlsFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, TlsGetCertNotBefore);
    lua_setglobal(luastate, "TlsGetCertNotBefore");

    lua_pushcfunction(luastate, TlsGetCertNotAfter);
    lua_setglobal(luastate, "TlsGetCertNotAfter");

    lua_pushcfunction(luastate, TlsGetVersion);
    lua_setglobal(luastate, "TlsGetVersion");

    lua_pushcfunction(luastate, TlsGetCertInfo);
    lua_setglobal(luastate, "TlsGetCertInfo");

    lua_pushcfunction(luastate, TlsGetSNI);
    lua_setglobal(luastate, "TlsGetSNI");

    lua_pushcfunction(luastate, TlsGetCertSerial);
    lua_setglobal(luastate, "TlsGetCertSerial");

    lua_pushcfunction(luastate, TlsGetCertChain);
    lua_setglobal(luastate, "TlsGetCertChain");

    return 0;
}

#endif /* HAVE_LUA */
