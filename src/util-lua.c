/* Copyright (C) 2014-2022 Open Information Security Foundation
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

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "util-lua.h"
#include "util-lua-sandbox.h"
#include "detect-lua-extensions.h"

lua_State *LuaGetState(void)
{
    lua_State *s = NULL;
    s = luaL_newstate();
    return s;
}

void LuaReturnState(lua_State *s)
{
    if (s != NULL) {
        /* clear the stack */
        while (lua_gettop(s) > 0) {
            lua_pop(s, 1);
        }
        lua_close(s);
    }
}

/* key for tv (threadvars) pointer */
const char lua_ext_key_tv[] = "suricata:lua:tv:ptr";
/* key for tx pointer */
const char lua_ext_key_tx[] = "suricata:lua:tx:ptr";
/* key for tx id */
const char lua_ext_key_tx_id[] = "suricata:lua:tx_id";
/* key for p (packet) pointer */
const char lua_ext_key_p[] = "suricata:lua:pkt:ptr";
/* key for f (flow) pointer */
const char lua_ext_key_flow[] = "suricata:lua:flow:ptr";
/* key for direction */
const char lua_ext_key_direction[] = "suricata:lua:direction";

/* key for pa (packet alert) pointer */
const char lua_ext_key_pa[] = "suricata:lua:pkt:alert:ptr";
/* key for s (signature) pointer */
const char lua_ext_key_s[] = "suricata:lua:signature:ptr";
/* key for file pointer */
const char lua_ext_key_file[] = "suricata:lua:file:ptr";
/* key for DetectEngineThreadCtx pointer */
const char lua_ext_key_det_ctx[] = "suricata:lua:det_ctx:ptr";

/*
 * Registry context values are wrapped in a typed userdata instead of
 * being stored as bare lightuserdata. In unsandboxed states the registry
 * is script-writable, so a bare pointer can be moved between keys and
 * re-cast by the libs (type confusion/UAF). The type id is checked on
 * every read; a retyped value fails the check and yields NULL.
 */
typedef struct SCLuaRegValue_ {
    uint32_t type_id;
    void *ptr;
} SCLuaRegValue;

enum {
    SCLUA_REG_INVALID = 0,
    SCLUA_REG_TV,
    SCLUA_REG_PACKET,
    SCLUA_REG_TX,
    SCLUA_REG_FLOW,
    SCLUA_REG_PACKET_ALERT,
    SCLUA_REG_SIGNATURE,
    SCLUA_REG_FILE,
    SCLUA_REG_DET_CTX,
    SCLUA_REG_DETECT_LUA_DATA,
};

static void LuaStateSetReg(lua_State *luastate, const void *key, uint32_t type_id, void *ptr)
{
    lua_pushlightuserdata(luastate, (void *)key);
    if (ptr == NULL) {
        /* clear without allocating (this runs at state teardown, where the
         * sandbox allocator may be over its cap): NULL a typed slot in
         * place, drop anything else (a nil settable never inserts) */
        lua_gettable(luastate, LUA_REGISTRYINDEX);
        if (lua_type(luastate, -1) == LUA_TUSERDATA &&
                lua_rawlen(luastate, -1) == sizeof(SCLuaRegValue)) {
            SCLuaRegValue *v = (SCLuaRegValue *)lua_touserdata(luastate, -1);
            if (v != NULL && v->type_id == type_id) {
                v->ptr = NULL;
                lua_pop(luastate, 1);
                return;
            }
        }
        lua_pop(luastate, 1);
        lua_pushlightuserdata(luastate, (void *)key);
        lua_pushnil(luastate);
        lua_settable(luastate, LUA_REGISTRYINDEX);
        return;
    }
    /* the registry survives across match calls: when the slot already
     * holds a value of this type, update it in place instead of paying
     * a fresh GC allocation on every set (hot path) */
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    if (lua_type(luastate, -1) == LUA_TUSERDATA &&
            lua_rawlen(luastate, -1) == sizeof(SCLuaRegValue)) {
        SCLuaRegValue *v = (SCLuaRegValue *)lua_touserdata(luastate, -1);
        if (v != NULL && v->type_id == type_id) {
            v->ptr = ptr;
            lua_pop(luastate, 1);
            return;
        }
    }
    lua_pop(luastate, 1);
    lua_pushlightuserdata(luastate, (void *)key);
    SCLuaRegValue *v = (SCLuaRegValue *)lua_newuserdata(luastate, sizeof(*v));
    v->type_id = type_id;
    v->ptr = ptr;
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

static void *LuaStateGetReg(lua_State *luastate, const void *key, uint32_t type_id)
{
    lua_pushlightuserdata(luastate, (void *)key);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    void *ptr = NULL;
    /* require the exact full-userdata shape before casting: a
     * lightuserdata or a foreign small userdata would otherwise be
     * re-read as SCLuaRegValue (OOB ptr on a size match) */
    if (lua_type(luastate, -1) == LUA_TUSERDATA &&
            lua_rawlen(luastate, -1) == sizeof(SCLuaRegValue)) {
        SCLuaRegValue *v = (SCLuaRegValue *)lua_touserdata(luastate, -1);
        if (v != NULL && v->type_id == type_id) {
            ptr = v->ptr;
        }
    }
    lua_pop(luastate, 1);
    return ptr;
}

/** \brief get tv pointer from the lua state */
ThreadVars *LuaStateGetThreadVars(lua_State *luastate)
{
    return (ThreadVars *)LuaStateGetReg(luastate, lua_ext_key_tv, SCLUA_REG_TV);
}

void LuaStateSetThreadVars(lua_State *luastate, ThreadVars *tv)
{
    LuaStateSetReg(luastate, lua_ext_key_tv, SCLUA_REG_TV, (void *)tv);
}

/** \brief get packet pointer from the lua state */
Packet *LuaStateGetPacket(lua_State *luastate)
{
    return (Packet *)LuaStateGetReg(luastate, lua_ext_key_p, SCLUA_REG_PACKET);
}

void LuaStateSetPacket(lua_State *luastate, Packet *p)
{
    LuaStateSetReg(luastate, lua_ext_key_p, SCLUA_REG_PACKET, (void *)p);
}

/** \brief get tx pointer from the lua state */
void *LuaStateGetTX(lua_State *luastate)
{
    return LuaStateGetReg(luastate, lua_ext_key_tx, SCLUA_REG_TX);
}

/** \brief get tx id from the lua state */
uint64_t LuaStateGetTxId(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tx_id);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    uint64_t tx_id = lua_tointeger(luastate, -1);
    lua_pop(luastate, 1);
    return tx_id;
}
void LuaStateSetTX(lua_State *luastate, void *txptr, const uint64_t tx_id)
{
    LuaStateSetReg(luastate, lua_ext_key_tx, SCLUA_REG_TX, txptr);
    if (txptr == NULL) {
        return; /* cleared: the id is read together with the slot */
    }

    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_tx_id);
    lua_pushinteger(luastate, tx_id);
    lua_settable(luastate, LUA_REGISTRYINDEX);
}

Flow *LuaStateGetFlow(lua_State *luastate)
{
    Flow *f = (Flow *)LuaStateGetReg(luastate, lua_ext_key_flow, SCLUA_REG_FLOW);

    return f;
}

void LuaStateSetFlow(lua_State *luastate, Flow *f)
{
    /* flow */
    LuaStateSetReg(luastate, lua_ext_key_flow, SCLUA_REG_FLOW, (void *)f);
}

/** \brief get packet alert pointer from the lua state */
PacketAlert *LuaStateGetPacketAlert(lua_State *luastate)
{
    return (PacketAlert *)LuaStateGetReg(luastate, lua_ext_key_pa, SCLUA_REG_PACKET_ALERT);
}

void LuaStateSetPacketAlert(lua_State *luastate, PacketAlert *pa)
{
    LuaStateSetReg(luastate, lua_ext_key_pa, SCLUA_REG_PACKET_ALERT, (void *)pa);
}

/** \brief get signature pointer from the lua state */
Signature *LuaStateGetSignature(lua_State *luastate)
{
    return (Signature *)LuaStateGetReg(luastate, lua_ext_key_s, SCLUA_REG_SIGNATURE);
}

void LuaStateSetSignature(lua_State *luastate, const Signature *s)
{
    LuaStateSetReg(luastate, lua_ext_key_s, SCLUA_REG_SIGNATURE, (void *)s);
}

/** \brief get file pointer from the lua state */
File *LuaStateGetFile(lua_State *luastate)
{
    return (File *)LuaStateGetReg(luastate, lua_ext_key_file, SCLUA_REG_FILE);
}

void LuaStateSetFile(lua_State *luastate, File *file)
{
    LuaStateSetReg(luastate, lua_ext_key_file, SCLUA_REG_FILE, (void *)file);
}

/** \brief get DetectEngineThreadCtx pointer from the lua state */
DetectEngineThreadCtx *LuaStateGetDetCtx(lua_State *luastate)
{
    return (DetectEngineThreadCtx *)LuaStateGetReg(
            luastate, lua_ext_key_det_ctx, SCLUA_REG_DET_CTX);
}

void LuaStateSetDetCtx(lua_State *luastate, DetectEngineThreadCtx *det_ctx)
{
    LuaStateSetReg(luastate, lua_ext_key_det_ctx, SCLUA_REG_DET_CTX, (void *)det_ctx);
}

/** \brief get the per-rule DetectLuaData */
DetectLuaData *LuaStateGetDetectLuaData(lua_State *luastate)
{
    return (DetectLuaData *)LuaStateGetReg(luastate, luaext_key_ld, SCLUA_REG_DETECT_LUA_DATA);
}

void LuaStateSetDetectLuaData(lua_State *luastate, DetectLuaData *ld)
{
    LuaStateSetReg(luastate, luaext_key_ld, SCLUA_REG_DETECT_LUA_DATA, (void *)ld);
}

/** \brief get packet pointer from the lua state */
int LuaStateGetDirection(lua_State *luastate)
{
    lua_pushlightuserdata(luastate, (void *)&lua_ext_key_direction);
    lua_gettable(luastate, LUA_REGISTRYINDEX);
    int dir = lua_toboolean(luastate, -1);
    lua_pop(luastate, 1);
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
    /* a NULL buffer is outside the lua_pushlstring contract even with
     * zero length; push the empty string instead (and clamp the length,
     * a NULL input has no content of its own) */
    if (input == NULL) {
        input = (const uint8_t *)"";
        input_len = 0;
    }
    lua_pushlstring(luastate, (char *)input, input_len);
    return 1;
}

int LuaPushInteger(lua_State *luastate, lua_Integer n)
{
    lua_pushinteger(luastate, n);
    return 1;
}
