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
 */

#ifndef SURICATA_UTIL_LUA_COMMON_H
#define SURICATA_UTIL_LUA_COMMON_H

#include "app-layer-protos.h"

#define DEFAULT_LUA_ALLOC_LIMIT       500000
#define DEFAULT_LUA_INSTRUCTION_LIMIT 500000

/*
 * The libs validate their handles with luaL_checkudata(), i.e. by
 * metatable identity only. In unsandboxed states setmetatable() /
 * debug.setmetatable() is reachable, so a script can give one lib's
 * userdata another lib's metatable and the FFI code would re-cast the
 * payload (type confusion / wrong drop size). Each library userdata
 * therefore carries an immutable header with a type id that the
 * helpers verify next to the metatable; a forged handle fails closed.
 */
#define SCLUA_UD_MAGIC 0x534C5541u /* "SLUA" */

typedef struct SCLuaUserDataHeader_ {
    uint32_t magic;
    uint32_t type_id;
} SCLuaUserDataHeader;

enum SCLuaUserDataTypes {
    SCLUA_TUD_INVALID = 0,
    SCLUA_TUD_SHA256 = 1,
    SCLUA_TUD_SHA1,
    SCLUA_TUD_MD5,
    SCLUA_TUD_FLOWVAR,
    SCLUA_TUD_FLOWINT,
    SCLUA_TUD_BYTEVAR,
    SCLUA_TUD_DATASET,
    SCLUA_TUD_RULE,
    SCLUA_TUD_FILE,
    SCLUA_TUD_FLOW,
    SCLUA_TUD_PACKET,
    SCLUA_TUD_TLS_STATE,
    SCLUA_TUD_HTTP_TX,
    SCLUA_TUD_DNS_TX,
    SCLUA_TUD_SMTP_TX,
    SCLUA_TUD_SSH_TX,
    SCLUA_TUD_NTP_TX,
    SCLUA_TUD_JA3_TX,
    SCLUA_TUD_DNP3_POINTS,
};

/*
 * Lifetime anchor for the tx userdata (SCLUA_TUD_*_TX, the TLS state
 * handle and the DNP3 points object). Each of those payloads starts
 * with a SCLuaTxRef, filled by SCLuaTxRefInit() at get_tx() time from
 * the flow the state is running on. The tx (or the whole app-layer
 * state) can be freed while a script keeps the handle in module
 * state; SCLuaTxRefResolve() looks the tx up on demand from (flow,
 * flow identity, alproto, tx id) and is enforced by the
 * SCLuaCheckUserData / SCLuaTestUserData entry points for every tx
 * type. The lua layer never stores a parser tx pointer, so there is
 * no dangling pointer to guard: a miss just means the tx (or its
 * state) is gone. The alproto pins the protocol against flow-address
 * reuse by another protocol; the flow identity pins the flow itself
 * against address reuse by a same-protocol flow.
 *
 * The identity is flow_hash plus the full start timestamp - not
 * FlowGetId(), which truncates the seconds to 16 bits and wraps the
 * usecs mod 65536: two attacker-influenced flows could digest to the
 * same id while the raw fields still differ.
 */
struct Flow_;
typedef struct SCLuaTxRef_ {
    struct Flow_ *flow;  /**< flow the handle was created on */
    uint32_t flow_hash;  /**< flow hash at creation */
    uint64_t start_sec;  /**< full startts seconds at creation */
    uint32_t start_usec; /**< startts usecs at creation */
    AppProto alproto;    /**< that flow's app proto at creation */
    uint64_t tx_id;      /**< tx id on that state */
} SCLuaTxRef;

/*
 * Fill the liveness anchor of a freshly created tx userdata. The
 * flow is taken from the state; the tx id comes with it.
 */
void SCLuaTxRefInit(lua_State *L, SCLuaTxRef *ref, uint64_t tx_id);

/*
 * \brief resolve the tx a (flow, tx id) anchor names, on demand
 *
 * The tx is looked up in the flow the state runs on now:
 * same flow, same protocol (the recorded alproto pins the protocol
 * against flow-address reuse), a live state, and the tx still on that
 * state's list (AppLayerParserGetTx). On a hit *tx receives the live
 * tx pointer - the only pointer ever handed to the accessors, never
 * stored - so dereferencing is always memory-safe. The handle names
 * its tx by id: if the state is freed and re-allocated and a fresh tx
 * reuses the id, a stale handle resolves to the fresh tx (live
 * memory, possibly different data) instead of failing closed.
 *
 * \retval 1 live: *tx set (when non-NULL)
 * \retval 0 stale: the tx or its state was freed, the handle is from
 *          another flow, or the flow address was reused (another
 *          protocol or a same-protocol flow)
 */
int SCLuaTxRefResolve(lua_State *L, const SCLuaTxRef *ref, void **tx);

/* accessor boilerplate: resolve the anchored tx or push nil and return */
#define SCLUA_RESOLVE_TX(L, refp, txvar)                                                           \
    void *txvar = NULL;                                                                            \
    if (!SCLuaTxRefResolve(L, (refp), &(txvar))) {                                                 \
        lua_pushnil(L);                                                                            \
        return 1;                                                                                  \
    }

/*
 * Allocate a library userdata with the type header. Returns the start
 * of the payload area (size bytes) and leaves the object on the stack;
 * set the metatable afterwards.
 */
void *SCLuaNewUserData(lua_State *L, uint32_t type_id, size_t size);

/*
 * Verify the object at idx has metatable mt and type id type_id, error
 * otherwise. Returns the payload start; the object is left as-is.
 * For the tx types the tx liveness anchor is verified as well and a
 * stale handle raises "tx no longer valid" instead of handing out a
 * dangling pointer.
 */
void *SCLuaCheckUserData(lua_State *L, int idx, const char *mt, uint32_t type_id);

/*
 * Tag-checked payload without the liveness check: raises on a type
 * mismatch, but a stale tx anchor still yields the payload. Callers
 * may only touch Lua-owned fields (e.g. a count cached at handle
 * creation), never the embedded parser-owned pointers.
 */
void *SCLuaCheckUserDataPayload(lua_State *L, int idx, const char *mt, uint32_t type_id);

/*
 * As SCLuaCheckUserData but a well-tagged stale handle yields NULL
 * instead of a raise, for types whose stale contract is a soft
 * failure (nil) rather than an error (the dnp3 lazy points object).
 */
void *SCLuaCheckUserDataSoft(lua_State *L, int idx, const char *mt, uint32_t type_id);

/*
 * As SCLuaCheckUserData but returns NULL instead of raising when the
 * object is absent, untagged or of another type (for __gc handlers,
 * where a forged handle must be skipped, not raised on). A tx handle
 * that is well-tagged but stale still raises: following a dangling
 * tx pointer is never an option.
 */
void *SCLuaTestUserData(lua_State *L, int idx, const char *mt, uint32_t type_id);

int LuaCallbackError(lua_State *luastate, const char *msg);
const char *LuaGetStringArgument(lua_State *luastate, int argc);

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value);
void LuaPushTableKeyValueBoolean(lua_State *luastate, const char *key, bool value);
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value);
void LuaPushTableKeyValueLString(
        lua_State *luastate, const char *key, const char *value, size_t len);
void LuaPushTableKeyValueArray(
        lua_State *luastate, const char *key, const uint8_t *value, size_t len);

int LuaStateNeedProto(lua_State *luastate, AppProto alproto);

#ifdef UNITTESTS
void SCLuaCommonRegisterTests(void);
#endif /* UNITTESTS */

/* hack to please scan-build. Even though LuaCallbackError *always*
 * returns 2, scan-build doesn't accept it and generates false
 * positives */
#define LUA_ERROR(msg)                                                                             \
    LuaCallbackError(luastate, (msg));                                                             \
    return 2

#endif /* SURICATA_UTIL_LUA_COMMON_H */
