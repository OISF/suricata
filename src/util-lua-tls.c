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
    char ssl_version[32] = "";
    switch (ssl_state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
            snprintf(ssl_version, sizeof(ssl_version), "UNDETERMINED");
            break;
        case SSL_VERSION_2:
            snprintf(ssl_version, sizeof(ssl_version), "SSLv2");
            break;
        case SSL_VERSION_3:
            snprintf(ssl_version, sizeof(ssl_version), "SSLv3");
            break;
        case TLS_VERSION_10:
            snprintf(ssl_version, sizeof(ssl_version), "TLSv1");
            break;
        case TLS_VERSION_11:
            snprintf(ssl_version, sizeof(ssl_version), "TLS 1.1");
            break;
        case TLS_VERSION_12:
            snprintf(ssl_version, sizeof(ssl_version), "TLS 1.2");
            break;
        default:
            snprintf(ssl_version, sizeof(ssl_version), "0x%04x",
                     ssl_state->server_connp.version);
            break;
    }

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

    int lock_hint = 0;
    Flow *f = LuaStateGetFlow(luastate, &lock_hint);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(f);
        r = GetCertInfo(luastate, f, direction);
        FLOWLOCK_UNLOCK(f);
    } else {
        r = GetCertInfo(luastate, f, direction);
    }
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

    int lock_hint = 0;
    Flow *f = LuaStateGetFlow(luastate, &lock_hint);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(f);
        r = GetSNI(luastate, f);
        FLOWLOCK_UNLOCK(f);
    } else {
        r = GetSNI(luastate, f);
    }
    return r;
}

/** \brief register tls lua extensions in a luastate */
int LuaRegisterTlsFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, TlsGetCertInfo);
    lua_setglobal(luastate, "TlsGetCertInfo");

    lua_pushcfunction(luastate, TlsGetSNI);
    lua_setglobal(luastate, "TlsGetSNI");

    return 0;
}

#endif /* HAVE_LUA */
