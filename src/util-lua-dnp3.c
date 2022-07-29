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

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"
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

static void DNP3PushPoints(lua_State *luastate, DNP3Object *object)
{
    DNP3Point *point;
    int i = 1;

    TAILQ_FOREACH(point, object->points, next) {
        lua_pushinteger(luastate, i++);
        lua_newtable(luastate);

        lua_pushliteral(luastate, "index");
        lua_pushinteger(luastate, point->index);
        lua_settable(luastate, -3);

        DNP3PushPoint(luastate, object, point);

        lua_settable(luastate, -3);
    }
}

static void DNP3PushObjects(lua_State *luastate, DNP3ObjectList *objects)
{
    DNP3Object *object = NULL;
    int i = 1;

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
        lua_newtable(luastate);
        DNP3PushPoints(luastate, object);
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
    DNP3PushLinkHeader(luastate, &tx->request_lh);
    lua_settable(luastate, -3);

    /* Transport header. */
    LUA_PUSHT_INT(luastate, "transport_header", tx->request_th);

    /* Application header. */
    lua_pushliteral(luastate, "application_header");
    lua_newtable(luastate);
    DNP3PushApplicationHeader(luastate, &tx->request_ah);
    lua_settable(luastate, -3);

    lua_pushliteral(luastate, "objects");
    lua_newtable(luastate);
    DNP3PushObjects(luastate, &tx->request_objects);
    lua_settable(luastate, -3);
}

static void DNP3PushResponse(lua_State *luastate, DNP3Transaction *tx)
{
    /* Link header. */
    lua_pushliteral(luastate, "link_header");
    lua_newtable(luastate);
    DNP3PushLinkHeader(luastate, &tx->response_lh);
    lua_settable(luastate, -3);

    /* Transport header. */
    LUA_PUSHT_INT(luastate, "transport_header", tx->response_th);

    /* Application header. */
    lua_pushliteral(luastate, "application_header");
    lua_newtable(luastate);
    DNP3PushApplicationHeader(luastate, &tx->response_ah);
    lua_settable(luastate, -3);

    /* Internal indicators. */
    LUA_PUSHT_INT(luastate, "indicators",
        tx->response_iin.iin1 << 8 | tx->response_iin.iin2);

    lua_pushliteral(luastate, "objects");
    lua_newtable(luastate);
    DNP3PushObjects(luastate, &tx->response_objects);
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

    LUA_PUSHT_INT(luastate, "has_request", tx->has_request);
    if (tx->has_request) {
        lua_pushliteral(luastate, "request");
        lua_newtable(luastate);
        LUA_PUSHT_INT(luastate, "done", tx->request_done);
        LUA_PUSHT_INT(luastate, "complete", tx->request_complete);
        DNP3PushRequest(luastate, tx);
        lua_settable(luastate, -3);
    }

    LUA_PUSHT_INT(luastate, "has_response", tx->has_response);
    if (tx->has_response) {
        lua_pushliteral(luastate, "response");
        lua_newtable(luastate);
        LUA_PUSHT_INT(luastate, "done", tx->response_done);
        LUA_PUSHT_INT(luastate, "complete", tx->response_complete);
        DNP3PushResponse(luastate, tx);
        lua_settable(luastate, -3);
    }

    return 1;
}

int LuaRegisterDNP3Functions(lua_State *luastate)
{
    lua_pushcfunction(luastate, DNP3GetTx);
    lua_setglobal(luastate, "DNP3GetTx");

    return 0;
}

#endif /* HAVE_LUA */
