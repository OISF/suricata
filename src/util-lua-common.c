/* Copyright (C) 2014-2021 Open Information Security Foundation
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

#include "threads.h"
#include "threadvars.h"

#include "output.h"
#include "util-conf.h"

#include "flow.h"
#include "app-layer-parser.h"

#include "lua.h"

#include "util-lua.h"
#include "util-lua-common.h"

void *SCLuaNewUserData(lua_State *L, uint32_t type_id, size_t size)
{
    uint8_t *block = (uint8_t *)lua_newuserdata(L, sizeof(SCLuaUserDataHeader) + size);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    h->magic = SCLUA_UD_MAGIC;
    h->type_id = type_id;
    return block + sizeof(SCLuaUserDataHeader);
}

/*
 * The types whose payload is a tx handle (SCLuaTxRef first member):
 * they wrap parser-owned memory that is freed at state teardown or on
 * per-tx eviction while a script may still hold the userdata.
 */
static int SCLuaUserDataIsTxType(uint32_t type_id)
{
    switch (type_id) {
        case SCLUA_TUD_HTTP_TX:
        case SCLUA_TUD_DNS_TX:
        case SCLUA_TUD_SMTP_TX:
        case SCLUA_TUD_SSH_TX:
        case SCLUA_TUD_NTP_TX:
        case SCLUA_TUD_JA3_TX:
        case SCLUA_TUD_TLS_STATE:
        case SCLUA_TUD_DNP3_POINTS:
            return 1;
        default:
            return 0;
    }
}

/*
 * Uniform liveness check for the tx types. Raises when the handle is
 * well-tagged but stale; a stale handle must fail closed, the accessors
 * must never see a dangling tx pointer.
 */
static void SCLuaTxRefStaleRaise(lua_State *L)
{
    luaL_error(L, "tx no longer valid: the transaction or its flow state was freed");
    /* luaL_error raises; the return keeps the fail-closed path
     * explicit if it ever did not */
}

static uint8_t *SCLuaUserDataPayload(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    void *block = luaL_testudata(L, idx, mt);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    if (h->magic != SCLUA_UD_MAGIC || h->type_id != type_id) {
        return NULL;
    }
    return (uint8_t *)block + sizeof(SCLuaUserDataHeader);
}

void *SCLuaCheckUserData(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    uint8_t *block = (uint8_t *)luaL_checkudata(L, idx, mt);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    if (h->magic != SCLUA_UD_MAGIC || h->type_id != type_id) {
        luaL_error(L, "invalid handle: type mismatch");
        /* luaL_error raises; the return keeps the fail-closed path
         * explicit if it ever did not */
        return NULL;
    }
    uint8_t *payload = block + sizeof(SCLuaUserDataHeader);
    if (SCLuaUserDataIsTxType(type_id) &&
            !SCLuaTxRefResolve(L, (const SCLuaTxRef *)payload, NULL)) {
        SCLuaTxRefStaleRaise(L);
        return NULL;
    }
    return payload;
}

void *SCLuaTestUserData(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    uint8_t *payload = SCLuaUserDataPayload(L, idx, mt, type_id);
    if (payload == NULL) {
        return NULL;
    }
    if (SCLuaUserDataIsTxType(type_id) &&
            !SCLuaTxRefResolve(L, (const SCLuaTxRef *)payload, NULL)) {
        SCLuaTxRefStaleRaise(L);
        return NULL;
    }
    return payload;
}

void *SCLuaCheckUserDataPayload(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    uint8_t *block = (uint8_t *)luaL_checkudata(L, idx, mt);
    if (block == NULL) {
        return NULL;
    }
    SCLuaUserDataHeader *h = (SCLuaUserDataHeader *)block;
    if (h->magic != SCLUA_UD_MAGIC || h->type_id != type_id) {
        luaL_error(L, "invalid handle: type mismatch");
        return NULL;
    }
    return block + sizeof(SCLuaUserDataHeader);
}

void *SCLuaCheckUserDataSoft(lua_State *L, int idx, const char *mt, uint32_t type_id)
{
    void *payload = SCLuaCheckUserDataPayload(L, idx, mt, type_id);
    if (payload == NULL) {
        return NULL;
    }
    if (SCLuaUserDataIsTxType(type_id) &&
            !SCLuaTxRefResolve(L, (const SCLuaTxRef *)payload, NULL)) {
        return NULL;
    }
    return payload;
}

void SCLuaTxRefInit(lua_State *L, SCLuaTxRef *ref, uint64_t tx_id)
{
    Flow *f = LuaStateGetFlow(L);
    ref->flow = f;
    if (f != NULL) {
        ref->flow_hash = f->flow_hash;
        ref->start_sec = SCTIME_SECS(f->startts);
        ref->start_usec = SCTIME_USECS(f->startts);
        ref->alproto = f->alproto;
    } else {
        ref->flow_hash = 0;
        ref->start_sec = 0;
        ref->start_usec = 0;
        ref->alproto = ALPROTO_UNKNOWN;
    }
    ref->tx_id = tx_id;
}

int SCLuaTxRefResolve(lua_State *L, const SCLuaTxRef *ref, void **tx)
{
    /* only the current flow is dereferenced; the recorded one is
     * compared by pointer and may itself be long gone */
    Flow *f = LuaStateGetFlow(L);
    if (f == NULL || ref->flow == NULL || f != ref->flow) {
        return 0;
    }
    /* flow address reused by another protocol: the pinned alproto
     * mismatches and resolving would read a foreign tx the accessors
     * would cast - fail closed */
    if (f->alproto != ref->alproto) {
        return 0;
    }
    /* same address and protocol: a same-protocol flow took the old
     * one's place - the flow identity (hash + full start ts) pins
     * the original flow */
    if (f->flow_hash != ref->flow_hash || SCTIME_SECS(f->startts) != ref->start_sec ||
            SCTIME_USECS(f->startts) != ref->start_usec) {
        return 0;
    }
    if (f->alstate == NULL || f->alproto == ALPROTO_UNKNOWN) {
        return 0;
    }
    /* the tx must still be on the live state's list: per-tx eviction
     * frees a tx while the state stays alive */
    void *t = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, ref->tx_id);
    if (t == NULL) {
        return 0;
    }
    if (tx != NULL) {
        *tx = t;
    }
    return 1;
}

int LuaCallbackError(lua_State *luastate, const char *msg)
{
    lua_pushnil(luastate);
    lua_pushstring(luastate, msg);
    return 2;
}

const char *LuaGetStringArgument(lua_State *luastate, int idx)
{
    /* get argument */
    if (!lua_isstring(luastate, idx))
        return NULL;
    const char *str = lua_tostring(luastate, idx);
    if (str == NULL)
        return NULL;
    if (strlen(str) == 0)
        return NULL;
    return str;
}

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value)
{
    lua_pushstring(luastate, key);
    lua_pushnumber(luastate, value);
    lua_settable(luastate, -3);
}

void LuaPushTableKeyValueBoolean(lua_State *luastate, const char *key, bool value)
{
    lua_pushstring(luastate, key);
    lua_pushboolean(luastate, value);
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value to the stack
 *
 *  If value is NULL, string "(null")" will be put on the stack.
 */
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value)
{
    lua_pushstring(luastate, key);
    lua_pushstring(luastate, value ? value : "(null)");
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value with length to the stack.
 */
void LuaPushTableKeyValueLString(
        lua_State *luastate, const char *key, const char *value, size_t len)
{
    lua_pushstring(luastate, key);
    lua_pushlstring(luastate, value, len);
    lua_settable(luastate, -3);
}

void LuaPushTableKeyValueArray(
        lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaPushStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

/*
 * Protocol check for the tx libs. Returns a plain boolean: 1 when the
 * flow's app protocol matches, 0 otherwise (including the no-flow
 * case). Errors are reported by the callers, so nothing is pushed on
 * the stack. The previous implementation returned
 * LuaCallbackError's 2 for the no-flow case, which the boolean callers
 * treat as a protocol match.
 */
int LuaStateNeedProto(lua_State *luastate, AppProto alproto)
{
    Flow *flow = LuaStateGetFlow(luastate);
    if (flow == NULL)
        return 0;

    return (alproto == flow->alproto);
}

/***** Unittests *****/

#ifdef UNITTESTS

#include "string.h"

#include "util-unittest.h"

/* wrapper around the common validation entry point: pushes a boolean
 * "validated" when the handle at index 1 passes, raises when it is a
 * stale tx handle */
static int TestTxHandleWrapper(lua_State *L)
{
    void *r = SCLuaTestUserData(L, 1, "suricata:dns:tx", SCLUA_TUD_DNS_TX);
    lua_pushboolean(L, r != NULL);
    return 1;
}

/* build a dns tx userdata carrying the given liveness anchor */
static void *TestNewDnsTxData(lua_State *L, const SCLuaTxRef *ref)
{
    void *ud = SCLuaNewUserData(L, SCLUA_TUD_DNS_TX, sizeof(*ref));
    if (ud == NULL) {
        return NULL;
    }
    memcpy(ud, ref, sizeof(*ref));
    luaL_getmetatable(L, "suricata:dns:tx");
    lua_setmetatable(L, -2);
    return ud;
}

/* a fake "current" flow the state runs on; only the fields
 * SCLuaTxRefResolve reads are set. ALPROTO_TLS: its GetTx returns
 * the state itself, so the resolution is exercised without a real
 * parser state */
static Flow *TestMakeFlow(void)
{
    Flow *f = calloc(1, sizeof(Flow));
    if (f == NULL) {
        return NULL;
    }
    f->alstate = (void *)0x1234;
    f->alproto = ALPROTO_TLS;
    f->proto = IPPROTO_TCP;
    return f;
}

static SCLuaTxRef TestMakeRef(const Flow *f)
{
    SCLuaTxRef ref;
    memset(&ref, 0, sizeof(ref));
    ref.flow = (Flow *)f;
    ref.flow_hash = f->flow_hash;
    ref.start_sec = SCTIME_SECS(f->startts);
    ref.start_usec = SCTIME_USECS(f->startts);
    ref.alproto = f->alproto;
    ref.tx_id = 0;
    return ref;
}

/**
 * \test the uniform tx resolution: a (flow, identity, alproto, tx id)
 * anchor naming the flow's live state resolves to the state's tx;
 * each failure mode is stale - handle from another (freed) flow,
 * state freed, no flow running, unknown proto, flow address reused
 * by another protocol, same-protocol flow reusing the address. The
 * evicted-tx case needs a real parser state (the tx-list lookup) and
 * is covered end to end by the lua-sbx UAF reproducers
 */
static int SCLuaTxRefResolveTest(void)
{
    lua_State *L = LuaGetState();
    FAIL_IF_NULL(L);

    Flow *f = TestMakeFlow();
    FAIL_IF_NULL(f);
    Flow *f2 = TestMakeFlow();
    FAIL_IF_NULL(f2);
    LuaStateSetFlow(L, f);

    SCLuaTxRef ref = TestMakeRef(f);
    void *tx = NULL;
    /* the anchor names the live state's tx */
    FAIL_IF_NOT(SCLuaTxRefResolve(L, &ref, &tx));
    FAIL_IF_NOT(tx == f->alstate);

    ref.flow = f2; /* the handle's flow is gone, another runs now */
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    ref = TestMakeRef(f);

    f->alstate = NULL; /* state freed, not yet re-allocated */
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    f->alstate = (void *)0x1234;

    LuaStateSetFlow(L, NULL); /* no flow running now */
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    LuaStateSetFlow(L, f);

    f->alproto = ALPROTO_UNKNOWN;
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    f->alproto = ALPROTO_TLS;

    /* the flow's address was reused by a flow of another protocol:
     * the pinned alproto mismatches, fail closed */
    f->alproto = ALPROTO_HTTP;
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    f->alproto = ALPROTO_TLS;

    /* same address and protocol: a same-protocol flow took the old
     * flow's place - the flow identity mismatches, fail closed */
    f->flow_hash = 42;
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    f->flow_hash = 0;
    f->startts.secs = 42;
    FAIL_IF_NOT(!SCLuaTxRefResolve(L, &ref, NULL));
    f->startts.secs = 0;

    LuaReturnState(L);
    free(f);
    free(f2);
    PASS;
}

/**
 * \test the common validation entry point fails closed on a stale tx
 * handle: it raises a lua error instead of handing out a dangling
 * pointer
 */
static int SCLuaTestUserDataStaleTest(void)
{
    lua_State *L = LuaGetState();
    FAIL_IF_NULL(L);

    luaL_newmetatable(L, "suricata:dns:tx");
    lua_pop(L, 1);

    Flow *f = TestMakeFlow();
    FAIL_IF_NULL(f);
    LuaStateSetFlow(L, f);

    SCLuaTxRef ref = TestMakeRef(f);
    f->alstate = NULL; /* stale: the state is gone */

    void *ud = TestNewDnsTxData(L, &ref);
    FAIL_IF_NULL(ud);

    int udidx = lua_gettop(L);
    lua_pushcfunction(L, TestTxHandleWrapper);
    lua_pushvalue(L, udidx);
    int rc = lua_pcall(L, 1, 0, 0);
    FAIL_IF_NOT(rc == LUA_ERRRUN);
    const char *err = lua_tostring(L, -1);
    FAIL_IF_NULL(err);
    FAIL_IF_NOT(strstr(err, "tx no longer valid") != NULL);
    lua_pop(L, 1);

    LuaReturnState(L);
    free(f);
    PASS;
}

/**
 * \test a live tx handle passes the common validation entry point and
 * a mistyped argument still fails quietly (the SCLuaTestUserData
 * contract), with no raise
 */
static int SCLuaTestUserDataLiveTest(void)
{
    lua_State *L = LuaGetState();
    FAIL_IF_NULL(L);

    luaL_newmetatable(L, "suricata:dns:tx");
    lua_pop(L, 1);

    Flow *f = TestMakeFlow();
    FAIL_IF_NULL(f);
    LuaStateSetFlow(L, f);

    SCLuaTxRef ref = TestMakeRef(f);
    void *ud = TestNewDnsTxData(L, &ref);
    FAIL_IF_NULL(ud);

    /* live handle: validation passes, the wrapper reports it */
    int udidx = lua_gettop(L);
    lua_pushcfunction(L, TestTxHandleWrapper);
    lua_pushvalue(L, udidx);
    int rc = lua_pcall(L, 1, 1, 0);
    FAIL_IF_NOT(rc == LUA_OK);
    FAIL_IF_NOT(lua_toboolean(L, -1));
    lua_pop(L, 1);

    /* mistyped argument: no metatable match, no raise */
    lua_pushinteger(L, 42);
    int numidx = lua_gettop(L);
    lua_pushcfunction(L, TestTxHandleWrapper);
    lua_pushvalue(L, numidx);
    rc = lua_pcall(L, 1, 1, 0);
    FAIL_IF_NOT(rc == LUA_OK);
    FAIL_IF_NOT(!lua_toboolean(L, -1));
    lua_pop(L, 1);

    LuaReturnState(L);
    free(f);
    PASS;
}

void SCLuaCommonRegisterTests(void)
{
    UtRegisterTest("SCLuaTxRefResolveTest", SCLuaTxRefResolveTest);
    UtRegisterTest("SCLuaTestUserDataStaleTest", SCLuaTestUserDataStaleTest);
    UtRegisterTest("SCLuaTestUserDataLiveTest", SCLuaTestUserDataLiveTest);
}

#endif /* UNITTESTS */
