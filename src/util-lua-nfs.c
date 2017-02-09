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
#include "app-layer-dns-common.h"
#include "app-layer.h"
#include "app-layer-parser.h"
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

#include "app-layer-nfs3tcp.h"

static int LuaGetNumberArgument(lua_State *luastate, int argc)
{
    /* get argument */
    if (!lua_isnumber(luastate, argc))
        return -1;
    int n = lua_tonumber(luastate, argc);
    return n;
}

static int NfsGetBuffer(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_NFS3TCP)))
        return LuaCallbackError(luastate, "error: protocol not nfs");

    const Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = f->alstate;
    if (state == NULL)
        return LuaCallbackError(luastate, "internal error: no state");

    int idx = LuaGetNumberArgument(luastate, 1);
    if (idx < 0)
        return LuaCallbackError(luastate, "internal error: invalid idx");

    uint8_t *data;
    uint32_t len;

    if (r_getdata(state, (uint32_t)idx, &data, &len) == 0)
        return LuaCallbackError(luastate, "error: not found");

    char *c = BytesToString(data, len);
    if (c == NULL)
        return LuaCallbackError(luastate, "internal error: bytes2string failure");

    size_t input_len = strlen(c);
    int ret = LuaPushStringBuffer(luastate, (uint8_t *)c, input_len);
    SCFree(c);
    return ret;
}

static int NfsGetU32(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_NFS3TCP)))
        return LuaCallbackError(luastate, "error: protocol not nfs");

    const Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = f->alstate;
    if (state == NULL)
        return LuaCallbackError(luastate, "internal error: no state");

    int idx = LuaGetNumberArgument(luastate, 1);
    if (idx < 0)
        return LuaCallbackError(luastate, "internal error: invalid idx");

    uint32_t value;

    if (r_getu32(state, (uint32_t)idx, &value) == 0)
        return LuaCallbackError(luastate, "error: not found");

    lua_pushinteger(luastate, value);
    return 1;
}

static int NfsGetU64(lua_State *luastate)
{
    if (!(LuaStateNeedProto(luastate, ALPROTO_NFS3TCP)))
        return LuaCallbackError(luastate, "error: protocol not nfs");

    const Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    void *state = f->alstate;
    if (state == NULL)
        return LuaCallbackError(luastate, "internal error: no state");

    int idx = LuaGetNumberArgument(luastate, 1);
    if (idx < 0)
        return LuaCallbackError(luastate, "internal error: invalid idx");

    uint64_t value;

    if (r_getu64(state, (uint32_t)idx, &value) == 0)
        return LuaCallbackError(luastate, "error: not found");

    lua_pushinteger(luastate, value);
    return 1;
}

/** \brief register nfs lua extensions in a luastate */
int LuaRegisterNfsFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, NfsGetBuffer);
    lua_setglobal(luastate, "NfsGetBuffer");
    lua_pushcfunction(luastate, NfsGetU32);
    lua_setglobal(luastate, "NfsGetU32");
    lua_pushcfunction(luastate, NfsGetU64);
    lua_setglobal(luastate, "NfsGetU64");
    return 0;
}

#endif /* HAVE_LUA */
