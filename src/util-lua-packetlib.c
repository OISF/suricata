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
 * Packet API for Lua.
 *
 * local packet = require("suricata.packet")
 */

#include "suricata-common.h"

#include "util-lua-packetlib.h"

#include "app-layer-protos.h" /* Required by util-lua-common. */
#include "util-lua-common.h"
#include "util-lua.h"
#include "util-debug.h"
#include "util-print.h"

/* key for p (packet) pointer */
extern const char lua_ext_key_p[];
static const char suricata_packet[] = "suricata:packet";

struct LuaPacket {
    Packet *p;
};

static int LuaPacketGC(lua_State *luastate)
{
    SCLogDebug("gc:start");
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    SCLogDebug("packet %p", s->p);
    s->p = NULL;
    SCLogDebug("gc:done");
    return 0;
}

static int LuaPacketPayload(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    LuaPushStringBuffer(luastate, (const uint8_t *)s->p->payload, (size_t)s->p->payload_len);
    return 1;
}

static int LuaPacketPacket(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    LuaPushStringBuffer(luastate, (const uint8_t *)GET_PKT_DATA(s->p), (size_t)GET_PKT_LEN(s->p));
    return 1;
}

static int LuaPacketPcapCnt(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    lua_pushinteger(luastate, s->p->pcap_cnt);
    return 1;
}

/** \internal
 *  \brief legacy format as used by fast.log, http.log, etc.
 */
static int LuaPacketTimestringLegacy(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    char timebuf[64];
    CreateTimeString(s->p->ts, timebuf, sizeof(timebuf));
    lua_pushstring(luastate, timebuf);
    return 1;
}

static int LuaPacketTimestringIso8601(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    char timebuf[64];
    CreateIsoTimeString(s->p->ts, timebuf, sizeof(timebuf));
    lua_pushstring(luastate, timebuf);
    return 1;
}

static int LuaPacketTimestamp(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    lua_pushnumber(luastate, (double)SCTIME_SECS(s->p->ts));
    lua_pushnumber(luastate, (double)SCTIME_USECS(s->p->ts));
    return 2;
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ipver (number), src ip (string), dst ip (string), protocol (number),
 *          sp or icmp type (number), dp or icmp code (number).
 */
static int LuaPacketTuple(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }
    Packet *p = s->p;

    int ipver = 0;
    if (PacketIsIPv4(p)) {
        ipver = 4;
    } else if (PacketIsIPv6(p)) {
        ipver = 6;
    }
    lua_pushinteger(luastate, ipver);
    if (ipver == 0)
        return 1;

    char srcip[46] = "", dstip[46] = "";
    if (PacketIsIPv4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PacketIsIPv6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }

    lua_pushstring(luastate, srcip);
    lua_pushstring(luastate, dstip);

    /* proto and ports (or type/code) */
    lua_pushinteger(luastate, p->proto);
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
        lua_pushinteger(luastate, p->sp);
        lua_pushinteger(luastate, p->dp);

    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        lua_pushinteger(luastate, p->icmp_s.type);
        lua_pushinteger(luastate, p->icmp_s.code);
    } else {
        lua_pushinteger(luastate, 0);
        lua_pushinteger(luastate, 0);
    }

    return 6;
}

/** \internal
 *  \brief get tcp/udp/sctp source port
 *  \param luastate the lua state
 */
static int LuaPacketSport(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }
    Packet *p = s->p;

    switch (p->proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            lua_pushinteger(luastate, p->sp);
            break;
        default:
            LUA_ERROR("sp only available for tcp, udp and sctp");
    }

    return 1;
}

/** \internal
 *  \brief get tcp/udp/sctp dest port
 *  \param luastate the lua state
 */
static int LuaPacketDport(lua_State *luastate)
{
    struct LuaPacket *s = (struct LuaPacket *)lua_touserdata(luastate, 1);
    if (s == NULL || s->p == NULL) {
        LUA_ERROR("failed to get packet");
    }
    Packet *p = s->p;

    switch (p->proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_SCTP:
            lua_pushinteger(luastate, p->dp);
            break;
        default:
            LUA_ERROR("dp only available for tcp, udp and sctp");
    }

    return 1;
}

static int LuaPacketGet(lua_State *luastate)
{
    Packet *p = LuaStateGetPacket(luastate);
    if (p == NULL) {
        LUA_ERROR("failed to get packet");
    }

    struct LuaPacket *s = (struct LuaPacket *)lua_newuserdata(luastate, sizeof(*s));
    if (s == NULL) {
        LUA_ERROR("failed to get userdata");
    }
    s->p = p;
    luaL_getmetatable(luastate, suricata_packet);
    lua_setmetatable(luastate, -2);
    return 1;
}

static const luaL_Reg packetlib[] = {
    // clang-format off
    { "get", LuaPacketGet },
    { NULL, NULL }
    // clang-format on
};

static const luaL_Reg packetlib_meta[] = {
    // clang-format off
    { "packet", LuaPacketPacket },
    { "payload", LuaPacketPayload },
    { "pcap_cnt", LuaPacketPcapCnt },
    { "timestring_legacy", LuaPacketTimestringLegacy },
    { "timestring_iso8601", LuaPacketTimestringIso8601 },
    { "timestamp", LuaPacketTimestamp },
    { "tuple", LuaPacketTuple },
    { "sp", LuaPacketSport },
    { "dp", LuaPacketDport },
    { "__gc", LuaPacketGC },
    { NULL, NULL }
    // clang-format on
};

int LuaLoadPacketLib(lua_State *luastate)
{
    luaL_newmetatable(luastate, suricata_packet);
    lua_pushvalue(luastate, -1);
    lua_setfield(luastate, -2, "__index");
    luaL_setfuncs(luastate, packetlib_meta, 0);

    luaL_newlib(luastate, packetlib);
    return 1;
}
