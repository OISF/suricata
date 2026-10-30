/* Copyright (C) 2015 Open Information Security Foundation
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

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "util-lua.h"
#include "util-lua-sandbox.h"
#include "util-lua-common.h"
#include "util-lua-dnp3.h"
#include "util-lua-dnp3-objects.h"

/**
 * \brief Helper macro to push key and integer value onto a table.
 */
#define LUA_PUSHT_INT(l, k, v) do {             \
        lua_pushliteral(luastate, k);           \
        lua_pushinteger(luastate, v);           \
        lua_settable(luastate, -3);             \
    } while (0);

static void SCLuaPushTableBoolean(lua_State *L, const char *key, bool val)
{
    lua_pushstring(L, key);
    lua_pushboolean(L, val);
    lua_settable(L, -3);
}

/*
 * The per-object points value is either a plain array of copied point
 * tables (point count up to DNP3_MAX_EAGER_POINTS) or, beyond that, a
 * userdata object with __len and __index metamethods: materializing
 * every point of a large response in get_tx() would exhaust the sandbox
 * budget, failing the whole call with a memory limit error and
 * silencing the rule. The userdata materializes an entry as a fresh
 * table on each indexed access; # stays bounded by the cached count.
 *
 * The userdata stores no parser pointers in its ref: the object is
 * re-derived from the resolved (flow, tx id) anchor on each cold
 * indexed access, so a freed tx can never be followed. With the soft
 * stale contract (9068) an index access after the tx is gone yields
 * nil and # still reports the cached count. The other tx userdata
 * raise on stale instead.
 *
 * A forward cursor caches (object, point, position) for the invocation
 * that set it: a tx cannot be freed while a script call runs, so a
 * matching (state, invocation generation) means the cached pointers are
 * still live and points[i] is O(delta) instead of O(i) - without the
 * cursor a numeric walk of n points costs n(n+1)/2 list steps.
 */
#define DNP3_MAX_EAGER_POINTS 32
#define DNP3_POINTS_MT        "sc.dnp3.points"

typedef struct LuaDnp3Points_ {
    SCLuaTxRef ref;      /* (flow, tx id) anchor for the originating tx */
    uint32_t object_idx; /* object position in the tx's objects list */
    uint32_t n_points;   /* count cached at creation */
    /* forward cursor, trusted only for the invocation that set it */
    uint64_t cursor_gen;
    DNP3Object *cursor_object;
    DNP3Point *cursor_point;
    uint32_t cursor_pos; /* 1-based index of cursor_point; 0 = none */
    /* pairs() walk cursor: own fields so a pairs() run and an __index
     * walk cannot invalidate each other; seeded only on success */
    uint64_t pairs_gen;
    DNP3Object *pairs_object;
    DNP3Point *pairs_point;
    uint32_t pairs_pos; /* 1-based index of pairs_point; 0 = none */
} LuaDnp3Points;

/* __len metamethod: argument 1 is the points userdata. Both
 * metamethods check the tagged handle: in unsandboxed states a script
 * can pull them off the metatable and call them with a foreign
 * argument; a table or nil must error, not get dereferenced. */
static int Dnp3PointsLen(lua_State *luastate)
{
    /* count cached at creation; the handle holds no parser pointers
     * (the object is re-derived on index access), so no liveness
     * check here: a stale handle still reports the count */
    LuaDnp3Points *pts =
            SCLuaCheckUserDataPayload(luastate, 1, DNP3_POINTS_MT, SCLUA_TUD_DNP3_POINTS);
    if (pts == NULL) {
        return luaL_error(luastate, "invalid dnp3 points handle");
    }
    lua_pushinteger(luastate, pts->n_points);
    return 1;
}

/* __index metamethod: argument 1 is the points userdata, 2 the key */
static int Dnp3PointsIndex(lua_State *luastate)
{
    /* plain type check: the cursor path below skips the resolve, and
     * the cold path resolves explicitly (a stale tx then yields nil,
     * the soft 9068 contract, without touching parser memory) */
    LuaDnp3Points *pts =
            SCLuaCheckUserDataPayload(luastate, 1, DNP3_POINTS_MT, SCLUA_TUD_DNP3_POINTS);
    if (pts == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    const lua_Integer i = lua_tointeger(luastate, 2);
    /* bounds against the cached count also rejects indices past
     * UINT32_MAX before any (uint32_t) cast */
    if (i < 1 || (uint64_t)i > pts->n_points) {
        lua_pushnil(luastate);
        return 1;
    }

    /* indices are 1-based */
    DNP3Object *object;
    DNP3Point *point;
    uint32_t idx;
    /* the generation is bumped once per invocation of this state, so a
     * mismatch means the invocation that set the cursor is over (a tx
     * can be evicted while its flow stays live); deinit() and close-time
     * finalizers run without an invocation, so also require the
     * invocation's flow to be the anchor flow (the registry flow is
     * cleared before deinit); the nonzero test keeps a state without the
     * slot from ever trusting the cursor */
    if (pts->cursor_gen != 0 && LuaStateGetInvocationGen(luastate) == pts->cursor_gen &&
            LuaStateGetFlow(luastate) == pts->ref.flow && pts->ref.flow != NULL &&
            pts->cursor_pos >= 1) {
        /* access at, ahead of, or behind the cursor in the invocation
         * that set it: the tx cannot have been freed, so a same-position
         * re-read is the cached point itself, a forward one continues
         * from the cursor, and a backward one steps back through the
         * TAILQ; monotone loops, either direction, stay O(n) */
        object = pts->cursor_object;
        point = pts->cursor_point;
        idx = pts->cursor_pos;
        while (idx < (uint32_t)i) {
            point = point->next.tqe_next;
            idx++;
            if (point == NULL) {
                break;
            }
        }
        /* the bounds check above keeps i >= 1, so the walk-back cannot
         * run past the first element (where TAILQ_PREV would wrap) */
        while (idx > (uint32_t)i) {
            point = TAILQ_PREV(point, DNP3PointList_, next);
            idx--;
        }
    } else {
        /* cold path: resolve the originating tx and re-derive the
         * object from it: the ref stores only the object position, so
         * a freed tx is never followed */
        void *txptr = NULL;
        if (!SCLuaTxRefResolve(luastate, &pts->ref, &txptr)) {
            lua_pushnil(luastate);
            return 1;
        }
        DNP3Transaction *tx = (DNP3Transaction *)txptr;
        object = NULL;
        uint32_t k = 0;
        TAILQ_FOREACH (object, &tx->objects, next) {
            if (k == pts->object_idx) {
                break;
            }
            k++;
        }
        if (object == NULL || k != pts->object_idx) {
            lua_pushnil(luastate);
            return 1;
        }
        point = TAILQ_FIRST(object->points);
        idx = 1;
        while (point != NULL && idx < (uint32_t)i) {
            point = point->next.tqe_next;
            idx++;
        }
        if (point == NULL) {
            lua_pushnil(luastate);
            return 1;
        }
    }

    if (point == NULL) {
        lua_pushnil(luastate);
        return 1;
    }

    lua_newtable(luastate);
    lua_pushinteger(luastate, point->index);
    lua_setfield(luastate, -2, "index");
    DNP3PushPoint(luastate, object, point);
    /* seed the cursor only on success: a cold-path overrun must not
     * leave the generation current while point/pos still describe the
     * previous invocation's point */
    pts->cursor_gen = LuaStateGetInvocationGen(luastate);
    pts->cursor_object = object;
    pts->cursor_point = point;
    pts->cursor_pos = idx;
    return 1;
}

/* __pairs generic iterator: arguments are the handle state and the last
 * returned position (0 = start); returns (position, point table) or no
 * values. Walks the resolved object's live list, so a freed tx or a
 * vanished object ends the loop quietly, matching the stale index
 * yielding nil. Straight-line runs continue from the pairs cursor (one
 * hop per step, O(n) total); a jump into the captured iterator falls
 * back to the cold walk. The cursor uses its own fields so it cannot
 * disturb the __index cursor. */
static int Dnp3PointsNext(lua_State *luastate)
{
    LuaDnp3Points *pts =
            SCLuaCheckUserDataPayload(luastate, 1, DNP3_POINTS_MT, SCLUA_TUD_DNP3_POINTS);
    if (pts == NULL) {
        return 0;
    }
    const lua_Integer pos = lua_tointeger(luastate, 2);
    if (pos < 0 || (uint64_t)pos + 1 > pts->n_points) {
        return 0;
    }

    DNP3Object *object;
    DNP3Point *point;
    /* continuation of a pairs() run in the invocation that seeded the
     * cursor: the control variable is exactly the position returned
     * last, so one hop from the cursor is enough; a tx cannot be freed
     * while the call runs */
    if (pts->pairs_gen != 0 && LuaStateGetInvocationGen(luastate) == pts->pairs_gen &&
            LuaStateGetFlow(luastate) == pts->ref.flow && pts->ref.flow != NULL && pos > 0 &&
            (uint32_t)pos == pts->pairs_pos) {
        object = pts->pairs_object;
        point = pts->pairs_point->next.tqe_next;
    } else {
        /* cold path: resolve the originating tx and re-derive the
         * object from it: the ref stores only the object position, so
         * a freed tx is never followed */
        void *txptr = NULL;
        if (!SCLuaTxRefResolve(luastate, &pts->ref, &txptr)) {
            return 0;
        }
        DNP3Transaction *tx = (DNP3Transaction *)txptr;
        object = NULL;
        uint32_t k = 0;
        TAILQ_FOREACH (object, &tx->objects, next) {
            if (k == pts->object_idx) {
                break;
            }
            k++;
        }
        if (object == NULL || k != pts->object_idx) {
            return 0;
        }
        point = TAILQ_FIRST(object->points);
        uint32_t idx = 1;
        while (point != NULL && idx <= (uint32_t)pos) {
            point = point->next.tqe_next;
            idx++;
        }
    }
    if (point == NULL) {
        return 0;
    }

    /* generic-for contract: the first return value (second-lowest of
     * the two) is the control variable, so the key goes down first
     * and the point table on top; the shape matches the eager copy */
    lua_pushinteger(luastate, pos + 1);
    lua_newtable(luastate);
    lua_pushinteger(luastate, point->index);
    lua_setfield(luastate, -2, "index");
    DNP3PushPoint(luastate, object, point);
    /* seed the cursor only on success */
    pts->pairs_gen = LuaStateGetInvocationGen(luastate);
    pts->pairs_object = object;
    pts->pairs_point = point;
    pts->pairs_pos = (uint32_t)(pos + 1);
    return 2;
}

/* __pairs metamethod: pairs(obj.points) must walk the lazy value the
 * same way the eager table is walked: (position, point table) for
 * 1..n, nothing past n. Pre-threshold objects already behaved that
 * way as plain tables, so scripts iterating pairs() keep working past
 * the threshold too. */
static int Dnp3PointsPairs(lua_State *luastate)
{
    LuaDnp3Points *pts =
            SCLuaCheckUserDataPayload(luastate, 1, DNP3_POINTS_MT, SCLUA_TUD_DNP3_POINTS);
    if (pts == NULL) {
        lua_pushnil(luastate);
        return 1;
    }
    lua_pushcfunction(luastate, Dnp3PointsNext);
    /* state: the handle; start before the first point */
    lua_pushvalue(luastate, 1);
    lua_pushinteger(luastate, 0);
    return 3;
}

static void DNP3PushObjectPoints(lua_State *luastate, DNP3Object *object, uint32_t object_idx)
{
    DNP3Point *p;
    uint32_t n = 0;
    TAILQ_FOREACH (p, object->points, next) {
        n++;
    }

    if (n <= DNP3_MAX_EAGER_POINTS) {
        /* small count: copy the points, the tables stay valid after the
         * tx is gone */
        lua_newtable(luastate);
        uint32_t i = 0;
        TAILQ_FOREACH (p, object->points, next) {
            i++;
            lua_pushinteger(luastate, i);
            lua_newtable(luastate);
            lua_pushinteger(luastate, p->index);
            lua_setfield(luastate, -2, "index");
            DNP3PushPoint(luastate, object, p);
            lua_settable(luastate, -3);
        }
        return;
    }

    LuaDnp3Points *pts =
            (LuaDnp3Points *)SCLuaNewUserData(luastate, SCLUA_TUD_DNP3_POINTS, sizeof(*pts));
    if (pts == NULL) {
        /* defensive: lua_newuserdata raises on OOM; checked like
         * the other SCLuaNewUserData call sites */
        lua_pushnil(luastate);
        return;
    }
    pts->object_idx = object_idx;
    pts->n_points = n;
    /* lua_newuserdata does not zero: start with no cursor and no
     * pairs run, so the iterator fast path cannot see stale values */
    pts->cursor_gen = 0;
    pts->cursor_object = NULL;
    pts->cursor_point = NULL;
    pts->cursor_pos = 0;
    pts->pairs_gen = 0;
    pts->pairs_object = NULL;
    pts->pairs_point = NULL;
    pts->pairs_pos = 0;
    SCLuaTxRefInit(luastate, &pts->ref, LuaStateGetTxId(luastate));
    /* stack: [.., obj_t, "points", ud] */

    if (luaL_newmetatable(luastate, DNP3_POINTS_MT)) {
        /* stack: [.., ud, mt]: fill once, on first use */
        lua_pushliteral(luastate, "__index");
        lua_pushcfunction(luastate, Dnp3PointsIndex);
        lua_settable(luastate, -3);
        lua_pushliteral(luastate, "__len");
        lua_pushcfunction(luastate, Dnp3PointsLen);
        lua_settable(luastate, -3);
        lua_pushliteral(luastate, "__pairs");
        lua_pushcfunction(luastate, Dnp3PointsPairs);
        lua_settable(luastate, -3);
    }
    /* stack: [.., obj_t, "points", ud, mt] */
    /* pops the mt, tags the userdata: ud becomes the top again */
    lua_setmetatable(luastate, -2);
    /* stack: [.., obj_t, "points", ud]: caller's settable sees ud */
}

static void DNP3PushObjects(lua_State *luastate, DNP3ObjectList *objects)
{
    DNP3Object *object = NULL;
    int i = 1;
    uint32_t obj_idx = 0;

    TAILQ_FOREACH(object, objects, next) {
        lua_pushinteger(luastate, i++);
        lua_newtable(luastate);

        lua_pushliteral(luastate, "group");
        lua_pushinteger(luastate, object->group);
        lua_settable(luastate, -3);

        lua_pushliteral(luastate, "variation");
        lua_pushinteger(luastate, object->variation);
        lua_settable(luastate, -3);

        lua_pushliteral(luastate, "points");
        DNP3PushObjectPoints(luastate, object, obj_idx++);
        lua_settable(luastate, -3);

        lua_settable(luastate, -3);
    }
}

static void DNP3PushLinkHeader(lua_State *luastate, DNP3LinkHeader *header)
{
    LUA_PUSHT_INT(luastate, "len", header->len);
    LUA_PUSHT_INT(luastate, "control", header->control);
    LUA_PUSHT_INT(luastate, "dst", header->dst);
    LUA_PUSHT_INT(luastate, "src", header->src);
    LUA_PUSHT_INT(luastate, "crc", header->crc);
}

static void DNP3PushApplicationHeader(lua_State *luastate,
    DNP3ApplicationHeader *header)
{
    LUA_PUSHT_INT(luastate, "control", header->control);
    LUA_PUSHT_INT(luastate, "function_code", header->function_code);
}

static void DNP3PushRequest(lua_State *luastate, DNP3Transaction *tx)
{
    /* Link header. */
    lua_pushliteral(luastate, "link_header");
    lua_newtable(luastate);
    DNP3PushLinkHeader(luastate, &tx->lh);
    lua_settable(luastate, -3);

    /* Transport header. */
    LUA_PUSHT_INT(luastate, "transport_header", tx->th);

    /* Application header. */
    lua_pushliteral(luastate, "application_header");
    lua_newtable(luastate);
    DNP3PushApplicationHeader(luastate, &tx->ah);
    lua_settable(luastate, -3);

    lua_pushliteral(luastate, "objects");
    lua_newtable(luastate);
    DNP3PushObjects(luastate, &tx->objects);
    lua_settable(luastate, -3);
}

static void DNP3PushResponse(lua_State *luastate, DNP3Transaction *tx)
{
    /* Link header. */
    lua_pushliteral(luastate, "link_header");
    lua_newtable(luastate);
    DNP3PushLinkHeader(luastate, &tx->lh);
    lua_settable(luastate, -3);

    /* Transport header. */
    LUA_PUSHT_INT(luastate, "transport_header", tx->th);

    /* Application header. */
    lua_pushliteral(luastate, "application_header");
    lua_newtable(luastate);
    DNP3PushApplicationHeader(luastate, &tx->ah);
    lua_settable(luastate, -3);

    /* Internal indicators. */
    LUA_PUSHT_INT(luastate, "indicators", tx->iin.iin1 << 8 | tx->iin.iin2);

    lua_pushliteral(luastate, "objects");
    lua_newtable(luastate);
    DNP3PushObjects(luastate, &tx->objects);
    lua_settable(luastate, -3);
}

static int DNP3GetTx(lua_State *luastate)
{
    if (!LuaStateNeedProto(luastate, ALPROTO_DNP3)) {
        return LuaCallbackError(luastate, "error: protocol not dnp3");
    }

    DNP3Transaction *tx = LuaStateGetTX(luastate);
    if (tx == NULL) {
        return LuaCallbackError(luastate, "error: no tx");
    }

    lua_newtable(luastate);

    lua_pushliteral(luastate, "tx_num");
    lua_pushinteger(luastate, tx->tx_num);
    lua_settable(luastate, -3);

    SCLuaPushTableBoolean(luastate, "is_request", tx->is_request);
    if (tx->is_request) {
        lua_pushliteral(luastate, "request");
        lua_newtable(luastate);
        SCLuaPushTableBoolean(luastate, "done", tx->done);
        SCLuaPushTableBoolean(luastate, "complete", tx->complete);
        DNP3PushRequest(luastate, tx);
        lua_settable(luastate, -3);
    } else {
        lua_pushliteral(luastate, "response");
        lua_newtable(luastate);
        SCLuaPushTableBoolean(luastate, "done", tx->done);
        SCLuaPushTableBoolean(luastate, "complete", tx->complete);
        DNP3PushResponse(luastate, tx);
        lua_settable(luastate, -3);
    }

    return 1;
}

static const struct luaL_Reg dnp3lib[] = {
    // clang-format off
    { "get_tx", DNP3GetTx, },
    { NULL, NULL, }
    // clang-format on
};

int SCLuaLoadDnp3Lib(lua_State *L)
{
    luaL_newlib(L, dnp3lib);
    return 1;
}
