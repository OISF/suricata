/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "util-lua-ja3.h"
#include "util-lua-tls.h"
#include "util-lua-ssh.h"
#include "util-lua-hassh.h"
#include "util-lua-smtp.h"
#include "util-lua-dnp3.h"
#include "detect-lua-extensions.h"

static const char luaext_key_ld[] = "suricata:luadata";

/* hack to please scan-build. Even though LuaCallbackError *always*
 * returns 2, scan-build doesn't accept it and generates false
 * positives */
#define LUA_ERROR(msg)                  \
    LuaCallbackError(luastate, (msg));  \
    return 2

static int GetLuaData(lua_State *luastate, DetectLuaData **ret_ld)
{
    *ret_ld = NULL;

    DetectLuaData *ld;
    lua_pushlightuserdata(luastate, (void *)&luaext_key_ld);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    ld = lua_touserdata(luastate, -1);
    if (ld == NULL) {
        LUA_ERROR("internal error: no ld");
    }
    *ret_ld = ld;
    return 0;
}

static int GetFlow(lua_State *luastate, Flow **ret_f)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL) {
        LUA_ERROR("no flow");
    }
    *ret_f = f;
    return 0;
}

static int GetFlowVarById(lua_State *luastate, Flow *f,
        FlowVar **ret_fv, bool fv_may_be_null, uint32_t *ret_idx)
{
    DetectLuaData *ld = NULL;
    if (ret_idx)
        *ret_idx = 0;
    *ret_fv = NULL;

    /* need lua data for id -> idx conversion */
    int ret = GetLuaData(luastate, &ld);
    if (ret != 0)
        return ret;

    if (!lua_isnumber(luastate, 1)) {
        LUA_ERROR("flowvar id not a number");
    }
    int id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        LUA_ERROR("flowvar id out of range");
    }
    uint32_t idx = ld->flowvar[id];
    if (idx == 0) {
        LUA_ERROR("flowvar id uninitialized");
    }
    FlowVar *fv = FlowVarGet(f, idx);
    if (!fv_may_be_null && fv == NULL) {
        LUA_ERROR("no flow var");
    }
    *ret_fv = fv;
    if (ret_idx)
        *ret_idx = idx;
    return 0;
}

static int GetFlowVarByKey(lua_State *luastate, Flow *f, FlowVar **ret_fv)
{
    *ret_fv = NULL;

    if (!lua_isstring(luastate, 1)) {
        LUA_ERROR("flowvar key not a string");
    }
    const char *keystr = lua_tostring(luastate, 1);
    if (keystr == NULL) {
        LUA_ERROR("key is null");
    }
    if (!lua_isnumber(luastate, 2)) {
        LUA_ERROR("key length not specified");
    }
    int keylen = lua_tonumber(luastate, 2);
    if (keylen < 0 || keylen > 0xff) {
        LUA_ERROR("key len out of range: max 256");
    }

    FlowVar *fv = FlowVarGetByKey(f, (const uint8_t *)keystr, keylen);
    if (fv == NULL) {
        LUA_ERROR("no flow var");
    }
    *ret_fv = fv;
    return 0;
}

static int GetFlowIntById(lua_State *luastate, Flow *f,
        FlowVar **ret_fv, bool fv_may_be_null, uint32_t *ret_idx)
{
    DetectLuaData *ld = NULL;
    if (ret_idx)
        *ret_idx = 0;
    *ret_fv = NULL;

    /* need lua data for id -> idx conversion */
    int ret = GetLuaData(luastate, &ld);
    if (ret != 0)
        return ret;

    if (!lua_isnumber(luastate, 1)) {
        LUA_ERROR("flowvar id not a number");
    }
    int id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        LUA_ERROR("flowvar id out of range");
    }
    uint32_t idx = ld->flowint[id];
    if (idx == 0) {
        LUA_ERROR("flowvar id uninitialized");
    }
    FlowVar *fv = FlowVarGet(f, idx);
    if (!fv_may_be_null && fv == NULL) {
        LUA_ERROR("no flow var");
    }
    *ret_fv = fv;
    if (ret_idx)
        *ret_idx = idx;
    return 0;
}

static int LuaGetFlowvar(lua_State *luastate)
{
    Flow *f;
    FlowVar *fv;
    int ret;

    /* need flow */
    ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    if (lua_isnumber(luastate, 1)) {
        ret = GetFlowVarById(luastate, f, &fv, false, NULL);
        if (ret != 0 || fv == NULL)
            return ret;
    } else if (lua_isstring(luastate, 1)) {
        ret = GetFlowVarByKey(luastate, f, &fv);
        if (ret != 0 || fv == NULL)
            return ret;
    } else {
        LUA_ERROR("invalid data type as first argument");
    }

    LuaPushStringBuffer(luastate,
            (const uint8_t *)fv->data.fv_str.value,
            (size_t)fv->data.fv_str.value_len);
    return 1;
}

static int LuaSetFlowvarById(lua_State *luastate)
{
    uint32_t idx = 0;
    Flow *f;
    const char *str;
    int len;
    uint8_t *buffer;
    FlowVar *fv = NULL;

    /* need flow */
    int ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    ret = GetFlowVarById(luastate, f, &fv, true, &idx);
    if (ret != 0)
        return ret;

    if (!lua_isstring(luastate, 2)) {
        LUA_ERROR("buffer not a string");
    }
    str = lua_tostring(luastate, 2);
    if (str == NULL) {
        LUA_ERROR("buffer is null");
    }

    if (!lua_isnumber(luastate, 3)) {
        LUA_ERROR("buffer length not specified");
    }
    len = lua_tonumber(luastate, 3);
    if (len < 0 || len > 0xffff) {
        LUA_ERROR("len out of range: max 64k");
    }

    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        LUA_ERROR("out of memory");
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';

    FlowVarAddIdValue(f, idx, buffer, len);
    return 0;
}

static int LuaSetFlowvarByKey(lua_State *luastate)
{
    Flow *f;
    const char *str;
    int len;
    uint8_t *buffer;

    /* need flow */
    int ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    const char *keystr = NULL;
    int keylen = 0;

    keystr = lua_tostring(luastate, 1);
    if (keystr == NULL) {
        LUA_ERROR("key is null");
    }
    if (!lua_isnumber(luastate, 2)) {
        LUA_ERROR("key length not specified");
    }
    keylen = lua_tonumber(luastate, 2);
    if (keylen < 0 || keylen > 0xff) {
        LUA_ERROR("key len out of range: max 256");
    }

    if (!lua_isstring(luastate, 3)) {
        LUA_ERROR("buffer not a string");
    }
    str = lua_tostring(luastate, 3);
    if (str == NULL) {
        LUA_ERROR("buffer is null");
    }

    if (!lua_isnumber(luastate, 4)) {
        LUA_ERROR("buffer length not specified");
    }
    len = lua_tonumber(luastate, 4);
    if (len < 0 || len > 0xffff) {
        LUA_ERROR("len out of range: max 64k");
    }

    buffer = SCMalloc(len+1);
    if (unlikely(buffer == NULL)) {
        LUA_ERROR("out of memory");
    }
    memcpy(buffer, str, len);
    buffer[len] = '\0';

    uint8_t *keybuf = SCMalloc(keylen+1);
    if (unlikely(keybuf == NULL)) {
        SCFree(buffer);
        LUA_ERROR("out of memory");
    }
    memcpy(keybuf, keystr, keylen);
    keybuf[keylen] = '\0';
    FlowVarAddKeyValue(f, keybuf, keylen, buffer, len);

    return 0;
}

static int LuaSetFlowvar(lua_State *luastate)
{
    if (lua_isnumber(luastate, 1)) {
        return LuaSetFlowvarById(luastate);
    } else {
        return LuaSetFlowvarByKey(luastate);
    }
}

static int LuaGetFlowint(lua_State *luastate)
{
    Flow *f;
    FlowVar *fv;
    uint32_t number;

    /* need flow */
    int ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    ret = GetFlowIntById(luastate, f, &fv, false, NULL);
    if (ret != 0)
        return ret;

    number = fv->data.fv_int.value;

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    return 1;

}

static int LuaSetFlowint(lua_State *luastate)
{
    uint32_t idx;
    Flow *f;
    DetectLuaData *ld;

    /* need lua data for id -> idx conversion */
    int ret = GetLuaData(luastate, &ld);
    if (ret != 0)
        return ret;

    /* need flow */
    ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    /* need flowint idx */
    if (!lua_isnumber(luastate, 1)) {
        LUA_ERROR("1st arg not a number");
    }
    int id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_FLOWVARS) {
        LUA_ERROR("flowint id out of range");
    }

    if (!lua_isnumber(luastate, 2)) {
        LUA_ERROR("2nd arg not a number");
    }
    lua_Number luanumber = lua_tonumber(luastate, 2);
    if (luanumber < 0 || id > (double)UINT_MAX) {
        LUA_ERROR("value out of range, "
                "value must be unsigned 32bit int");
    }
    uint32_t number = (uint32_t)luanumber;

    idx = ld->flowint[id];
    if (idx == 0) {
        LUA_ERROR("flowint id uninitialized");
    }

    FlowVarAddInt(f, idx, number);

    SCLogDebug("stored flow:%p idx:%u value:%u", f, idx, number);
    return 0;
}

static int LuaIncrFlowint(lua_State *luastate)
{
    uint32_t idx;
    Flow *f;
    FlowVar *fv;
    uint32_t number;

    /* need flow */
    int ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    ret = GetFlowIntById(luastate, f, &fv, true, &idx);
    if (ret != 0)
        return ret;

    if (fv == NULL) {
        number = 1;
    } else {
        number = fv->data.fv_int.value;
        if (number < UINT_MAX)
            number++;
    }
    FlowVarAddIntNoLock(f, idx, number);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("incremented flow:%p idx:%u value:%u", f, idx, number);
    return 1;

}

static int LuaDecrFlowint(lua_State *luastate)
{
    uint32_t idx;
    Flow *f;
    FlowVar *fv;
    uint32_t number;

    /* need flow */
    int ret = GetFlow(luastate, &f);
    if (ret != 0)
        return ret;

    ret = GetFlowIntById(luastate, f, &fv, true, &idx);
    if (ret != 0)
        return ret;

    if (fv == NULL) {
        number = 0;
    } else {
        number = fv->data.fv_int.value;
        if (number > 0)
            number--;
    }
    FlowVarAddIntNoLock(f, idx, number);

    /* return value through luastate, as a luanumber */
    lua_pushnumber(luastate, (lua_Number)number);
    SCLogDebug("decremented flow:%p idx:%u value:%u", f, idx, number);
    return 1;

}

static int LuaGetByteVar(lua_State *luastate)
{
    DetectLuaData *ld = NULL;
    DetectEngineThreadCtx *det_ctx = LuaStateGetDetCtx(luastate);

    if (det_ctx == NULL)
        return LuaCallbackError(luastate, "internal error: no ldet_ctx");

    int ret = GetLuaData(luastate, &ld);
    if (ret != 0)
        return ret;

    if (!lua_isnumber(luastate, 1)) {
        LUA_ERROR("bytevar id not a number");
    }
    int id = lua_tonumber(luastate, 1);
    if (id < 0 || id >= DETECT_LUAJIT_MAX_BYTEVARS) {
        LUA_ERROR("bytevar id out of range");
    }
    uint32_t idx = ld->bytevar[id];

    lua_pushinteger(luastate, det_ctx->byte_values[idx]);

    return 1;
}

void LuaExtensionsMatchSetup(lua_State *lua_state, DetectLuaData *ld,
        DetectEngineThreadCtx *det_ctx, Flow *f, Packet *p, const Signature *s, uint8_t flags)
{
    SCLogDebug("det_ctx %p, f %p", det_ctx, f);

    /* lua keyword data */
    lua_pushlightuserdata(lua_state, (void *)&luaext_key_ld);
    lua_pushlightuserdata(lua_state, (void *)ld);
    lua_settable(lua_state, LUA_REGISTRYINDEX);

    LuaStateSetSignature(lua_state, s);

    LuaStateSetFlow(lua_state, f);
    LuaStateSetDetCtx(lua_state, det_ctx);

    if (det_ctx->tx_id_set) {
        if (f && f->alstate) {
            void *txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, det_ctx->tx_id);
            if (txptr) {
                LuaStateSetTX(lua_state, txptr, det_ctx->tx_id);
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

    lua_pushcfunction(lua_state, LuaGetFlowvar);
    lua_setglobal(lua_state, "SCFlowvarGet");

    lua_pushcfunction(lua_state, LuaSetFlowvar);
    lua_setglobal(lua_state, "ScFlowvarSet");

    lua_pushcfunction(lua_state, LuaSetFlowvar);
    lua_setglobal(lua_state, "SCFlowvarSet");

    lua_pushcfunction(lua_state, LuaGetFlowint);
    lua_setglobal(lua_state, "ScFlowintGet");

    lua_pushcfunction(lua_state, LuaGetFlowint);
    lua_setglobal(lua_state, "SCFlowintGet");

    lua_pushcfunction(lua_state, LuaSetFlowint);
    lua_setglobal(lua_state, "ScFlowintSet");

    lua_pushcfunction(lua_state, LuaSetFlowint);
    lua_setglobal(lua_state, "SCFlowintSet");

    lua_pushcfunction(lua_state, LuaIncrFlowint);
    lua_setglobal(lua_state, "ScFlowintIncr");

    lua_pushcfunction(lua_state, LuaIncrFlowint);
    lua_setglobal(lua_state, "SCFlowintIncr");

    lua_pushcfunction(lua_state, LuaDecrFlowint);
    lua_setglobal(lua_state, "ScFlowintDecr");

    lua_pushcfunction(lua_state, LuaDecrFlowint);
    lua_setglobal(lua_state, "SCFlowintDecr");

    lua_pushcfunction(lua_state, LuaGetByteVar);
    lua_setglobal(lua_state, "SCByteVarGet");

    LuaRegisterFunctions(lua_state);
    LuaRegisterHttpFunctions(lua_state);
    LuaRegisterDnsFunctions(lua_state);
    LuaRegisterJa3Functions(lua_state);
    LuaRegisterTlsFunctions(lua_state);
    LuaRegisterSshFunctions(lua_state);
    LuaRegisterHasshFunctions(lua_state);
    LuaRegisterSmtpFunctions(lua_state);
    LuaRegisterDNP3Functions(lua_state);
    return 0;
}

#endif /* HAVE_LUA */
