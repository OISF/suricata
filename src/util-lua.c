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

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"

#ifdef HAVE_LUAJIT
#include "util-luajit.h"
#endif

lua_State *LuaGetState(void)
{
    lua_State *s = NULL;
#ifdef HAVE_LUAJIT
    s = LuajitGetState();
#else
    s = luaL_newstate();
#endif
    return s;
}

void LuaReturnState(lua_State *s)
{
    if (s != NULL) {
        /* clear the stack */
        while (lua_gettop(s) > 0) {
            lua_pop(s, 1);
        }
#ifdef HAVE_LUAJIT
        LuajitReturnState(s);
#else
        lua_close(s);
#endif
    }
}

/* key for tv (threadvars) pointer */
const char lua_ext_key_tv[] = "suricata:lua:tv:ptr";
/* key for tx pointer */
const char lua_ext_key_tx[] = "suricata:lua:tx:ptr";
/* key for p (packet) pointer */
const char lua_ext_key_p[] = "suricata:lua:pkt:ptr";
/* key for f (flow) pointer */
const char lua_ext_key_flow[] = "suricata:lua:flow:ptr";
/* key for flow lock hint bool */
const char lua_ext_key_flow_lock_hint[] = "suricata:lua:flow:lock_hint";
/* key for direction */
const char lua_ext_key_direction[] = "suricata:lua:direction";

/* key for pa (packet alert) pointer */
const char lua_ext_key_pa[] = "suricata:lua:pkt:alert:ptr";
/* key for s (signature) pointer */
const char lua_ext_key_s[] = "suricata:lua:signature:ptr";
/* key for file pointer */
const char lua_ext_key_file[] = "suricata:lua:file:ptr";
/* key for streaming buffer pointer */
const char lua_ext_key_streaming_buffer[] = "suricata:lua:streaming_buffer:ptr";

/** \brief get tv pointer from the lua state */
ThreadVars *LuaStateGetThreadVars(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tv);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *tv = lua_touserdata(luastate, -1);
    return (ThreadVars *)tv;
}

void LuaStateSetThreadVars(lua_State *luastate, ThreadVars *tv)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tv);
    lua_pushlightuserdata(luastate, (void *)tv);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

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

Flow *LuaStateGetFlow(lua_State *luastate)
{
    Flow *f = NULL;

    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    f = lua_touserdata(luastate, -1);

    /* need flow lock hint */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow_lock_hint);
    lua_gettable(luastate, LUA_REGISTRYINDEX);

    return f;
}

void LuaStateSetFlow(lua_State *luastate, Flow *f)
{
    /* flow */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow);
    lua_pushlightuserdata(luastate, (void *)f);
    lua_settable(luastate, LUA_REGISTRYINDEX);

    /* flow lock status hint */
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_flow_lock_hint);
    /* locking is not required, set to 0 for backwards compatibility */
    lua_pushboolean(luastate, 0);
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

/** \brief get signature pointer from the lua state */
Signature *LuaStateGetSignature(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_s);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *s = lua_touserdata(luastate, -1);
    return (Signature *)s;
}

void LuaStateSetSignature(lua_State *luastate, const Signature *s)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_s);
    lua_pushlightuserdata(luastate, (void *)s);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

/** \brief get file pointer from the lua state */
File *LuaStateGetFile(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_file);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *file = lua_touserdata(luastate, -1);
    return (File *)file;
}

void LuaStateSetFile(lua_State *luastate, File *file)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_file);
    lua_pushlightuserdata(luastate, (void *)file);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

LuaStreamingBuffer *LuaStateGetStreamingBuffer(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_streaming_buffer);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *b = lua_touserdata(luastate, -1);
    return (LuaStreamingBuffer *)b;
}

void LuaStateSetStreamingBuffer(lua_State *luastate, LuaStreamingBuffer *b)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_streaming_buffer);
    lua_pushlightuserdata(luastate, (void *)b);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

/** \brief get packet pointer from the lua state */
int LuaStateGetDirection(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_direction);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    int dir = lua_toboolean(luastate, -1);
    return dir;
}

void LuaStateSetDirection(lua_State *luastate, int direction)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_direction);
    lua_pushboolean(luastate, direction);
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

int LuaPushStringBuffer(lua_State *luastate, const uint8_t *input, size_t input_len)
{
    if (input_len % 4 != 0) {
        /* we're using a buffer sized at a multiple of 4 as lua_pushlstring generates
         * invalid read errors in valgrind otherwise. Adding in a nul to be sure.
         *
         * Buffer size = len + 1 (for nul) + whatever makes it a multiple of 4 */
        size_t buflen = input_len + 1 + ((input_len + 1) % 4);
        uint8_t buf[buflen];
        memset(buf, 0x00, buflen);
        memcpy(buf, input, input_len);
        buf[input_len] = '\0';

        /* return value through luastate, as a luastring */
        lua_pushlstring(luastate, (char *)buf, input_len);
    } else {
        lua_pushlstring(luastate, (char *)input, input_len);
    }
    return 1;
}

int LuaPushInteger(lua_State *luastate, lua_Integer n)
{
    lua_pushinteger(luastate, n);
    return 1;
}

#endif /* HAVE_LUA */
