/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Functions to expose to the lua scripts.
 */

#include "suricata-common.h"
#include "conf.h"

#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-flowvar.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-lua.h"

#include "queue.h"
#include "util-cpu.h"

#include "app-layer-parser.h"

#ifdef HAVE_LUA

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-http.h"
#include "util-lua-dns.h"
#include "util-lua-tls.h"
#include "util-lua-ssh.h"

static const char luaext_key_ld[] = "suricata:luajitdata";
static const char luaext_key_det_ctx[] = "suricata:det_ctx";

static int LuaGetFlowvar(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuaData *ld;
    int flow_lock = 0;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowvar idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id out of range");
        return 2;
    }
    idx = ld->flowvar[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id uninitialized");
        return 2;
    }

    /* lookup var */
    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
            FLOWLOCK_UNLOCK(f);

        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow var");
        return 2;
    }

    LuaPushStringBuffer(luastate, (const uint8_t *)fv->data.fv_str.value,
            (size_t)fv->data.fv_str.value_len);

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_UNLOCK(f);

    return 1;

}

int LuaSetFlowvar(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    const char *str;
    int len;
    uint8_t *buffer;
    DetectEngineThreadCtx *det_ctx;
    DetectLuaData *ld;
    int flow_lock = 0;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowvar idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id out of range");
        return 2;
    }

    if (!lua_isstring(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a string");
        return 2;
    }
    str = lua_tostring(luastate, 2);
    if (str == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "null string");
        return 2;
    }

    if (!lua_isnumber(luastate, 3)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "3rd arg not a number");
        return 2;
    }
    len = lua_tonumber(luastate, 3);
    if (len < 0 || len > 0xffff) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "len out of range: max 64k");
        return 2;
    }

    idx = ld->flowvar[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowvar id uninitialized");
        return 2;
    }

    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "out of memory");
        return 2;
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FlowVarAddStr(f, idx, buffer, len);
    else
        FlowVarAddStrNoLock(f, idx, buffer, len);

    //SCLogInfo("stored:");
    //PrintRawDataFp(stdout,buffer,len);
    return 0;
}

static int LuaGetFlowint(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuaData *ld;
    int flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        SCLogDebug("fv NULL");
        if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
            FLOWLOCK_UNLOCK(f);

        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow var");
        return 2;
    }
    number = fv->data.fv_int.value;

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("retrieved flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}

int LuaSetFlowint(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    DetectEngineThreadCtx *det_ctx;
    DetectLuaData *ld;
    int flow_lock = 0;
    uint32_t number;
    lua_Number luanumber;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need det_ctx */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_det_ctx);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    det_ctx = lua_touserdata(luastate, -1);
    SCLogDebug("det_ctx %p", det_ctx);
    if (det_ctx == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no det_ctx");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }

    if (!lua_isnumber(luastate, 2)) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "2nd arg not a number");
        return 2;
    }
    luanumber = lua_tonumber(luastate, 2);
    if (luanumber < 0 || id > (double)UINT_MAX) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "value out of range, value must be unsigned 32bit int");
        return 2;
    }
    number = (uint32_t)luanumber;

    idx = ld->flowint[id];
    if (idx == 0) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FlowVarAddInt(f, idx, number);
    else
        FlowVarAddIntNoLock(f, idx, number);

    SCLogDebug("stored flow:%p idx:%u value:%u", f, idx, number);
    return 0;
}

static int LuaIncrFlowint(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuaData *ld;
    int flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        number = 1;
    } else {
        number = fv->data.fv_int.value;
        if (number < UINT_MAX)
            number++;
    }
    FlowVarAddIntNoLock(f, idx, number);

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("incremented flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}

static int LuaDecrFlowint(lua_State *luastate)
{
    uint16_t idx;
    int id;
    Flow *f;
    FlowVar *fv;
    DetectLuaData *ld;
    int flow_lock = 0;
    uint32_t number;

    /* need luajit data for id -> idx conversion */
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    SCLogDebug("ld %p", ld);
    if (ld == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "internal error: no ld");
        return 2;
    }

    /* need flow and lock hint */
    f = LuaStateGetFlow(luastate, &flow_lock);
    if (f == NULL) {
        lua_pushnil(luastate);
        lua_pushstring(luastate, "no flow");
        return 2;
    }

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        SCLogDebug("1st arg not a number");
        lua_pushnil(luastate);
        lua_pushstring(luastate, "1st arg not a number");
        return 2;
    }
    id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWINTS) {
        SCLogDebug("id %d", id);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id out of range");
        return 2;
    }
    idx = ld->flowint[id];
    if (idx == 0) {
        SCLogDebug("idx %u", idx);
        lua_pushnil(luastate);
        lua_pushstring(luastate, "flowint id uninitialized");
        return 2;
    }

    /* lookup var */
    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_RDLOCK(f);

    fv = FlowVarGet(f, idx);
    if (fv == NULL) {
        number = 0;
    } else {
        number = fv->data.fv_int.value;
        if (number > 0)
            number--;
    }
    FlowVarAddIntNoLock(f, idx, number);

    if (flow_lock == LUA_FLOW_NOT_LOCKED_BY_PARENT)
        FLOWLOCK_UNLOCK(f);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("decremented flow:%p idx:%u value:%u", f, idx, number);

    return 1;

}

void LuaExtensionsMatchSetup(lua_State *lua_state, DetectLuaData *ld, DetectEngineThreadCtx *det_ctx,
        Flow *f, int flow_locked, Packet *p, uint8_t flags)
{
    SCLogDebug("det_ctx %p, f %p", det_ctx, f);

    /* luajit keyword data */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_ld);
    lua_pushlightuserdata(lua_state, (void *)ld);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    /* detection engine thread ctx */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_det_ctx);
    lua_pushlightuserdata(lua_state, (void *)det_ctx);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    LuaStateSetFlow(lua_state, f, flow_locked);

    if (det_ctx->tx_id_set && flow_locked == LUA_FLOW_LOCKED_BY_PARENT) {
        if (f && f->alstate) {
            void *txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, det_ctx->tx_id);
            if (txptr) {
                LuaStateSetTX(lua_state, txptr);
            }
        }
    }

    if (p != NULL)
        LuaStateSetPacket(lua_state, p);

    LuaStateSetDirection(lua_state, (flags & STREAM_TOSERVER));
}

/**
 *  \brief Register Suricata Lua functions
 */
int LuaRegisterExtensions(lua_State *lua_state)
{
    lua_pushcfunction(lua_state, LuaGetFlowvar);
    lua_setglobal(lua_state, "ScFlowvarGet");

    lua_pushcfunction(lua_state, LuaSetFlowvar);
    lua_setglobal(lua_state, "ScFlowvarSet");

    lua_pushcfunction(lua_state, LuaGetFlowint);
    lua_setglobal(lua_state, "ScFlowintGet");

    lua_pushcfunction(lua_state, LuaSetFlowint);
    lua_setglobal(lua_state, "ScFlowintSet");

    lua_pushcfunction(lua_state, LuaIncrFlowint);
    lua_setglobal(lua_state, "ScFlowintIncr");

    lua_pushcfunction(lua_state, LuaDecrFlowint);
    lua_setglobal(lua_state, "ScFlowintDecr");

    LuaRegisterFunctions(lua_state);
    LuaRegisterHttpFunctions(lua_state);
    LuaRegisterDnsFunctions(lua_state);
    LuaRegisterTlsFunctions(lua_state);
    LuaRegisterSshFunctions(lua_state);
    return 0;
}

#endif /* HAVE_LUA */
