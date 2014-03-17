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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Common function for Lua
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
#include "app-layer-htp.h"
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

/* key for tx pointer */
const char lua_ext_key_tx[] = "suricata:lua:tx:ptr";
/* key for p (packet) pointer */
const char lua_ext_key_p[] = "suricata:lua:pkt:ptr";
/* key for f (flow) pointer */
const char lua_ext_key_flow[] = "suricata:lua:flow:ptr";
/* key for flow lock hint bool */
const char lua_ext_key_flow_lock_hint[] = "suricata:lua:flow:lock_hint";

/* key for pa (packet alert) pointer */
const char lua_ext_key_pa[] = "suricata:lua:pkt:alert:ptr";

/** \brief get packet pointer from the lua state */
Packet *LuaStateGetPacket(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_p);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *p = lua_touserdata(luastate, -1);
    return (Packet *)p;
}

void LuaStateSetPacket(lua_State *luastate, Packet *p)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_p);
    lua_pushlightuserdata(luastate, (void *)p);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

/** \brief get tx pointer from the lua state */
void *LuaStateGetTX(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *tx = lua_touserdata(luastate, -1);
    return tx;
}

void LuaStateSetTX(lua_State *luastate, void *txptr)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tx);
    lua_pushlightuserdata(luastate, (void *)txptr);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

Flow *LuaStateGetFlow(lua_State *luastate, int *lock_hint)
{
    Flow *f = NULL;
    int need_flow_lock = 0;

    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow_lock_hint);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    need_flow_lock = lua_toboolean(luastate, -1);

    *lock_hint = need_flow_lock;
    return f;
}

void LuaStateSetFlow(lua_State *luastate, Flow *f, int need_flow_lock)
{
    /* flow */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow);
    lua_pushlightuserdata(luastate, (void *)f);
    lua_settable(luastate, LUA_REGISTRYINDEX);

    /* flow lock status hint */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow_lock_hint);
    lua_pushboolean(luastate, need_flow_lock);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

/** \brief get packet alert pointer from the lua state */
PacketAlert *LuaStateGetPacketAlert(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_pa);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *pa = lua_touserdata(luastate, -1);
    return (PacketAlert *)pa;
}

void LuaStateSetPacketAlert(lua_State *luastate, PacketAlert *pa)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_pa);
    lua_pushlightuserdata(luastate, (void *)pa);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

/** \brief dump stack from lua state to screen */
void LuaPrintStack(lua_State *state) {
    int size = lua_gettop(state);
    int i;

    for (i = 1; i <= size; i++) {
        int type = lua_type(state, i);
        printf("Stack size=%d, level=%d, type=%d, ", size, i, type);

        switch (type) {
            case LUA_TFUNCTION:
                printf("function %s", lua_tostring(state, i) ? "true" : "false");
                break;
            case LUA_TBOOLEAN:
                printf("bool %s", lua_toboolean(state, i) ? "true" : "false");
                break;
            case LUA_TNUMBER:
                printf("number %g", lua_tonumber(state, i));
                break;
            case LUA_TSTRING:
                printf("string `%s'", lua_tostring(state, i));
                break;
            case LUA_TTABLE:
                printf("table `%s'", lua_tostring(state, i));
                break;
            default:
                printf("other %s", lua_typename(state, type));
                break;

        }
        printf("\n");
    }
}




#endif /* HAVE_LUA */
