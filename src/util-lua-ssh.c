/* Copyright (C) 2022 Open Information Security Foundation
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
#include "app-layer-ssh.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "rust.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-ssh.h"

static int GetServerProtoVersion(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");
    const uint8_t *protocol = NULL;
    uint32_t b_len = 0;

    void *tx = rs_ssh_state_get_tx(state, 0);
    if (rs_ssh_tx_get_protocol(tx, &protocol, &b_len, STREAM_TOCLIENT) != 1)
        return LuaCallbackError(luastate, "error: no server proto version");
    if (protocol == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no server proto version");
    }

    return LuaPushStringBuffer(luastate, protocol, b_len);
}

static int SshGetServerProtoVersion(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_SSH)))
        return LuaCallbackError(luastate, "error: protocol not ssh");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetServerProtoVersion(luastate, f);

    return r;
}

static int GetServerSoftwareVersion(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    const uint8_t *software = NULL;
    uint32_t b_len = 0;

    void *tx = rs_ssh_state_get_tx(state, 0);
    if (rs_ssh_tx_get_software(tx, &software, &b_len, STREAM_TOCLIENT) != 1)
        return LuaCallbackError(luastate, "error: no server software version");
    if (software == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no server software version");
    }

    return LuaPushStringBuffer(luastate, software, b_len);
}

static int SshGetServerSoftwareVersion(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_SSH)))
        return LuaCallbackError(luastate, "error: protocol not ssh");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetServerSoftwareVersion(luastate, f);

    return r;
}

static int GetClientProtoVersion(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    const uint8_t *protocol = NULL;
    uint32_t b_len = 0;

    void *tx = rs_ssh_state_get_tx(state, 0);
    if (rs_ssh_tx_get_protocol(tx, &protocol, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no client proto version");
    if (protocol == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no client proto version");
    }

    return LuaPushStringBuffer(luastate, protocol, b_len);
}

static int SshGetClientProtoVersion(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_SSH)))
        return LuaCallbackError(luastate, "error: protocol not ssh");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetClientProtoVersion(luastate, f);

    return r;
}

static int GetClientSoftwareVersion(lua_State *luastate, const Flow *f)
{
    void *state = FlowGetAppState(f);
    if (state == NULL)
        return LuaCallbackError(luastate, "error: no app layer state");

    const uint8_t *software = NULL;
    uint32_t b_len = 0;

    void *tx = rs_ssh_state_get_tx(state, 0);
    if (rs_ssh_tx_get_software(tx, &software, &b_len, STREAM_TOSERVER) != 1)
        return LuaCallbackError(luastate, "error: no client software version");
    if (software == NULL || b_len == 0) {
        return LuaCallbackError(luastate, "error: no client software version");
    }

    return LuaPushStringBuffer(luastate, software, b_len);
}

static int SshGetClientSoftwareVersion(lua_State *luastate)
{
    int r;

    if (!(LuaStateNeedProto(luastate, ALPROTO_SSH)))
        return LuaCallbackError(luastate, "error: protocol not ssh");

    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    r = GetClientSoftwareVersion(luastate, f);

    return r;
}

/** \brief register ssh lua extensions in a luastate */
int LuaRegisterSshFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, SshGetServerProtoVersion);
    lua_setglobal(luastate, "SshGetServerProtoVersion");

    lua_pushcfunction(luastate, SshGetServerSoftwareVersion);
    lua_setglobal(luastate, "SshGetServerSoftwareVersion");

    lua_pushcfunction(luastate, SshGetClientProtoVersion);
    lua_setglobal(luastate, "SshGetClientProtoVersion");

    lua_pushcfunction(luastate, SshGetClientSoftwareVersion);
    lua_setglobal(luastate, "SshGetClientSoftwareVersion");

    return 0;
}

#endif /* HAVE_LUA */
