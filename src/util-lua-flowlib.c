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

/**
 * \file
 *
 * Flow API fow Lua.
 *
 * local flow = require("suricata.flow")
 */

#include "suricata-common.h"

#include "util-lua-flowlib.h"

#include "app-layer-protos.h" /* Required by util-lua-common. */
#include "util-lua-common.h"
#include "util-lua.h"
#include "util-debug.h"
#include "util-print.h"

/* key for f (flow) pointer */
extern const char lua_ext_key_f[];
static const char suricata_flow[] = "suricata:flow";

struct LuaFlow {
    Flow *f;
};

static int LuaFlowGC(lua_State *luastate)
{
    SCLogDebug("gc:start");
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    SCLogDebug("flow %p", s->f);
    s->f = NULL;
    SCLogDebug("gc:done");
    return 0;
}

/** \internal
 *  \brief fill lua stack with flow id
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: flow id (number)
 */
static int LuaFlowId(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;

    int64_t id = (int64_t)FlowGetId(f);
    lua_pushinteger(luastate, id);
    return 1;
}

/** \internal
 *  \brief fill lua stack with AppLayerProto
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: alproto as string (string), alproto_ts as string (string),
 *          alproto_tc as string (string), alproto_orig as string (string),
 *          alproto_expect as string (string)
 */
static int LuaFlowAppLayerProto(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    lua_pushstring(luastate, AppProtoToString(f->alproto));
    lua_pushstring(luastate, AppProtoToString(f->alproto_ts));
    lua_pushstring(luastate, AppProtoToString(f->alproto_tc));
    lua_pushstring(luastate, AppProtoToString(f->alproto_orig));
    lua_pushstring(luastate, AppProtoToString(f->alproto_expect));
    return 5;
}

/** \internal
 *  \brief fill lua stack with flow has alerts
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: alerts (bool)
 */
static int LuaFlowHasAlerts(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    lua_pushboolean(luastate, FlowHasAlerts(f));
    return 1;
}

/** \internal
 *  \brief fill lua stack with flow stats
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ts pkts (number), ts bytes (number), tc pkts (number), tc bytes (number)
 */
static int LuaFlowStats(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    lua_pushinteger(luastate, f->todstpktcnt);
    lua_pushinteger(luastate, f->todstbytecnt);
    lua_pushinteger(luastate, f->tosrcpktcnt);
    lua_pushinteger(luastate, f->tosrcbytecnt);
    return 4;
}

/** \internal
 *  \brief fill lua stack with flow timestamps
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: seconds (number), seconds (number), microseconds (number),
 *          microseconds (number)
 */
static int LuaFlowTimestamps(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    lua_pushnumber(luastate, (double)SCTIME_SECS(f->startts));
    lua_pushnumber(luastate, (double)SCTIME_SECS(f->lastts));
    lua_pushnumber(luastate, (double)SCTIME_USECS(f->startts));
    lua_pushnumber(luastate, (double)SCTIME_USECS(f->lastts));
    return 4;
}

static int LuaFlowTimestringIso8601(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    char timebuf[64];
    CreateIsoTimeString(f->startts, timebuf, sizeof(timebuf));
    lua_pushstring(luastate, timebuf);
    return 1;
}

/** \internal
 *  \brief legacy format as used by fast.log, http.log, etc.
 */
static int LuaFlowTimestringLegacy(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    Flow *f = s->f;
    char timebuf[64];
    CreateTimeString(f->startts, timebuf, sizeof(timebuf));
    lua_pushstring(luastate, timebuf);
    return 1;
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ipver (number), src ip (string), dst ip (string), protocol (number),
 *          sp or icmp type (number), dp or icmp code (number).
 */
static int LuaFlowTuple(lua_State *luastate)
{
    struct LuaFlow *s = (struct LuaFlow *)lua_touserdata(luastate, 1);
    if (s == NULL || s->f == NULL) {
        LUA_ERROR("failed to get flow");
    }
    Flow *f = s->f;
    int ipver = 0;
    if (FLOW_IS_IPV4(f)) {
        ipver = 4;
    } else if (FLOW_IS_IPV6(f)) {
        ipver = 6;
    }
    lua_pushinteger(luastate, ipver);
    if (ipver == 0)
        return 1;

    char srcip[46] = "", dstip[46] = "";
    if (FLOW_IS_IPV4(f)) {
        PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dstip, sizeof(dstip));
    } else if (FLOW_IS_IPV6(f)) {
        PrintInet(AF_INET6, (const void *)&(f->src.address), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)&(f->dst.address), dstip, sizeof(dstip));
    }

    lua_pushstring(luastate, srcip);
    lua_pushstring(luastate, dstip);

    /* proto and ports (or type/ code) */
    lua_pushinteger(luastate, f->proto);
    if (f->proto == IPPROTO_TCP || f->proto == IPPROTO_UDP) {
        lua_pushinteger(luastate, f->sp);
        lua_pushinteger(luastate, f->dp);
    } else if (f->proto == IPPROTO_ICMP || f->proto == IPPROTO_ICMPV6) {
        lua_pushinteger(luastate, f->icmp_s.type);
        lua_pushinteger(luastate, f->icmp_s.code);
    } else {
        lua_pushinteger(luastate, 0);
        lua_pushinteger(luastate, 0);
    }
    return 6;
}

static int LuaFlowGet(lua_State *luastate)
{
    Flow *f = LuaStateGetFlow(luastate);
    if (f == NULL) {
        LUA_ERROR("failed to get flow");
    }

    struct LuaFlow *s = (struct LuaFlow *)lua_newuserdata(luastate, sizeof(*s));
    if (s == NULL) {
        LUA_ERROR("failed to allocate userdata");
    }
    s->f = f;
    luaL_getmetatable(luastate, suricata_flow);
    lua_setmetatable(luastate, -2);
    return 1;
}

static const luaL_Reg flowlib[] = {
    // clang-format off
    { "get", LuaFlowGet },
    { NULL, NULL }
    // clang-format on
};

static const luaL_Reg flowlib_meta[] = {
    // clang-format off
    { "id", LuaFlowId },
    { "app_layer_proto", LuaFlowAppLayerProto },
    { "has_alerts", LuaFlowHasAlerts },
    { "stats", LuaFlowStats },
    { "timestamps", LuaFlowTimestamps },
    { "timestring_iso8601", LuaFlowTimestringIso8601 },
    { "timestring_legacy", LuaFlowTimestringLegacy },
    { "tuple", LuaFlowTuple },
    { "__gc", LuaFlowGC },
    { NULL, NULL }
    // clang-format on
};

int LuaLoadFlowLib(lua_State *luastate)
{
    luaL_newmetatable(luastate, suricata_flow);
    lua_pushvalue(luastate, -1);
    lua_setfield(luastate, -2, "__index");
    luaL_setfuncs(luastate, flowlib_meta, 0);

    luaL_newlib(luastate, flowlib);
    return 1;
}
