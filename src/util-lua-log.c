/* Copyright (C) 2025 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-lua-log.h"
#include "util-lua.h"
#include "util-debug.h"

#include "lauxlib.h"

static bool LuaGetAr(lua_State *L, lua_Debug *ar)
{
    if (lua_getstack(L, 1, ar) && lua_getinfo(L, "nSl", ar)) {
        return true;
    }
    return false;
}

static int LuaLogInfo(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogInfoRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogInfo("%s", msg);
    }
    return 0;
}

static int LuaLogNotice(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogNoticeRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogNotice("%s", msg);
    }

    return 0;
}

static int LuaLogWarning(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogWarningRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogWarning("%s", msg);
    }
    return 0;
}

static int LuaLogError(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogErrorRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogError("%s", msg);
    }
    return 0;
}

static int LuaLogDebug(lua_State *L)
{
#ifdef DEBUG
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogDebugRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogDebug("%s", msg);
    }
#endif
    return 0;
}

static int LuaLogConfig(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogConfigRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogConfig("%s", msg);
    }
    return 0;
}

static int LuaLogPerf(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    lua_Debug ar;
    if (LuaGetAr(L, &ar)) {
        const char *funcname = ar.name ? ar.name : ar.what;
        SCLogPerfRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    } else {
        SCLogPerf("%s", msg);
    }
    return 0;
}

static const struct luaL_Reg loglib[] = {
    // clang-format off
    { "info", LuaLogInfo },
    { "notice", LuaLogNotice },
    { "warning", LuaLogWarning },
    { "error", LuaLogError },
    { "debug", LuaLogDebug },
    { "config", LuaLogConfig },
    { "perf", LuaLogPerf },
    { NULL, NULL }
    // clang-format on
};

int SCLuaLoadLogLib(lua_State *L)
{
    luaL_newlib(L, loglib);
    return 1;
}
