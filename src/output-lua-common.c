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
 * Common function for Lua Output
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

extern const char lualog_ext_key_tx;
extern const char lualog_ext_key_p;

Packet *LuaStateGetPacket(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lualog_ext_key_p);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *p = lua_touserdata(luastate, -1);
    return (Packet *)p;
}

void *LuaStateGetTX(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lualog_ext_key_tx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *tx = lua_touserdata(luastate, -1);
    return tx;
}

int LuaCallbackError(lua_State *luastate, const char *msg)
{
    lua_pushnil(luastate);
    lua_pushstring(luastate, msg);
    return 2;
}

int LuaReturnStringBuffer(lua_State *luastate, const uint8_t *input, size_t input_len)
{
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
    return 1;
}

const char *LuaGetStringArgument(lua_State *luastate, int argc)
{
    /* get argument */
    if (!lua_isstring(luastate, argc))
        return NULL;
    const char *str = lua_tostring(luastate, argc);
    if (str == NULL)
        return NULL;
    if (strlen(str) == 0)
        return NULL;
    return str;
}

void LogLuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value)
{
    lua_pushstring(luastate, key);
    lua_pushnumber(luastate, value);
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value to the stack
 *
 *  If value is NULL, string "(null")" will be put on the stack.
 */
void LogLuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value)
{
    lua_pushstring(luastate, key);
    lua_pushstring(luastate, value ? value : "(null)");
    lua_settable(luastate, -3);
}

void LogLuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaReturnStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ipver (number), src ip (string), dst ip (string), protocol (number),
 *          sp or icmp type (number), dp or icmp code (number).
 */
static int LuaCallbackTuplePushToStackFromPacket(lua_State *luastate, const Packet *p)
{
    int ipver = 0;
    if (PKT_IS_IPV4(p)) {
        ipver = 4;
    } else if (PKT_IS_IPV6(p)) {
        ipver = 6;
    }
    lua_pushnumber (luastate, ipver);
    if (ipver == 0)
        return 1;

    char srcip[46] = "", dstip[46] = "";
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }

    lua_pushstring (luastate, srcip);
    lua_pushstring (luastate, dstip);

    /* proto and ports (or type/code) */
    lua_pushnumber (luastate, p->proto);
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
        lua_pushnumber (luastate, p->sp);
        lua_pushnumber (luastate, p->dp);

    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        lua_pushnumber (luastate, p->type);
        lua_pushnumber (luastate, p->code);
    } else {
        lua_pushnumber (luastate, 0);
        lua_pushnumber (luastate, 0);
    }

    return 6;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackTuple(lua_State *luastate)
{
    const Packet *p = LuaStateGetPacket(luastate);
    if (p == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackTuplePushToStackFromPacket(luastate, p);
}

static int LuaCallbackLogPath(lua_State *luastate)
{
    const char *ld = ConfigGetLogDirectory();
    if (ld == NULL)
        return LuaCallbackError(luastate, "internal error: no log dir");

    return LuaReturnStringBuffer(luastate, (const uint8_t *)ld, strlen(ld));
}

static int LuaCallbackLogDebug(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogDebug("%s", msg);
    return 0;
}

static int LuaCallbackLogInfo(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogInfo("%s", msg);
    return 0;
}

static int LuaCallbackLogNotice(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogNotice("%s", msg);
    return 0;
}

static int LuaCallbackLogWarning(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogWarning(SC_WARN_LUA_SCRIPT, "%s", msg);
    return 0;
}

static int LuaCallbackLogError(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogError(SC_ERR_LUA_SCRIPT, "%s", msg);
    return 0;
}

int LogLuaRegisterFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, LuaCallbackTuple);
    lua_setglobal(luastate, "SCPacketTuple");
    lua_pushcfunction(luastate, LuaCallbackLogPath);
    lua_setglobal(luastate, "SCLogPath");

    lua_pushcfunction(luastate, LuaCallbackLogDebug);
    lua_setglobal(luastate, "SCLogDebug");
    lua_pushcfunction(luastate, LuaCallbackLogInfo);
    lua_setglobal(luastate, "SCLogInfo");
    lua_pushcfunction(luastate, LuaCallbackLogNotice);
    lua_setglobal(luastate, "SCLogNotice");
    lua_pushcfunction(luastate, LuaCallbackLogWarning);
    lua_setglobal(luastate, "SCLogWarning");
    lua_pushcfunction(luastate, LuaCallbackLogError);
    lua_setglobal(luastate, "SCLogError");
    return 0;
}

#endif /* HAVE_LUA */
