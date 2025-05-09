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

static const char tls_flow[] = "suricata:tls";

struct LuaTls {
    Flow *f; // flow
};

static int LuaTlsFlowGet(lua_State *luastate)
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
    s->f = f;
    luaL_getmetatable(luastate, tls_flow);
    lua_setmetatable(luastate, -2);
    return 1;
}

static int GetCertNotBefore(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    int direction = LuaStateGetDirection(luastate);
    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_before == 0)
        return LuaCallbackError(luastate, "error: no certificate NotBefore");

    return LuaPushInteger(luastate, connp->cert0_not_before);
}

static int LuaTlsGetCertNotBefore(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertNotBefore(luastate, s->f);
}

static int GetCertNotAfter(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    int direction = LuaStateGetDirection(luastate);
    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_not_after == 0)
        return LuaCallbackError(luastate, "error: no certificate NotAfter");

    return LuaPushInteger(luastate, connp->cert0_not_after);
}

static int LuaTlsGetCertNotAfter(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertNotAfter(luastate, s->f);
}

static int GetCertInfo(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    int direction = LuaStateGetDirection(luastate);
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

static int LuaTlsGetCertInfo(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertInfo(luastate, s->f);
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

static int LuaTlsGetSNI(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    return GetSNI(luastate, s->f);
}

static int GetCertChain(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    int direction = LuaStateGetDirection(luastate);
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

static int LuaTlsGetCertChain(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    if (!(LuaStateNeedProto(luastate, ALPROTO_TLS)))
        return LuaCallbackError(luastate, "error: protocol not tls");

    return GetCertChain(luastate, s->f);
}

static int GetCertSerial(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;
    SSLStateConnp *connp = NULL;

    int direction = LuaStateGetDirection(luastate);
    if (direction) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }
    if (connp->cert0_serial == NULL)
        return LuaCallbackError(luastate, "error: no certificate serial");

    return LuaPushStringBuffer(
            luastate, (uint8_t *)connp->cert0_serial, strlen(connp->cert0_serial));
}

static int LuaTlsGetCertSerial(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetCertSerial(luastate, s->f);
}

static int GetAgreedVersion(lua_State *luastate, Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    SSLState *ssl_state = (SSLState *)state;

    int direction = LuaStateGetDirection(luastate);

    int version;
    if (direction) {
        version = ssl_state->client_connp.version;
    } else {
        version = ssl_state->server_connp.version;
    }

    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(version, ssl_version);

    lua_pushstring(luastate, (const char *)&ssl_version);
    return 1;
}

static int LuaTlsGetVersion(lua_State *luastate)
{
    struct LuaTls *s = (struct LuaTls *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    return GetAgreedVersion(luastate, s->f);
}

static const struct luaL_Reg tlslib_meta[] = {
    // clang-format off
    { "get_cert_not_before", LuaTlsGetCertNotBefore },
    { "get_cert_not_after", LuaTlsGetCertNotAfter },
    { "get_version", LuaTlsGetVersion },
    { "get_serial", LuaTlsGetCertSerial },
    { "get_cert_info", LuaTlsGetCertInfo },
    { "get_sni", LuaTlsGetSNI },
    { "get_cert_chain", LuaTlsGetCertChain },
    { NULL, NULL, }
    // clang-format on
};

static const struct luaL_Reg tlslib[] = {
    // clang-format off
    { "get", LuaTlsFlowGet },
    { NULL, NULL,},
    // clang-format on
};

int SCLuaLoadTlsLib(lua_State *L)
{
    luaL_newmetatable(L, tls_flow);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, tlslib_meta, 0);

    luaL_newlib(L, tlslib);
    return 1;
}
