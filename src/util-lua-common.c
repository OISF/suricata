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
 *
 * Common function for Lua Output
 */

#include "suricata-common.h"
#include "debug.h"
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

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"

int LuaCallbackError(lua_State *luastate, const char *msg)
{
    lua_pushnil(luastate);
    lua_pushstring(luastate, msg);
    return 2;
}

const char *LuaGetStringArgument(lua_State *luastate, int argc)
{
    /* get argument */
    if (!lua_isstring(luastate, argc))
        return NULL;
    const char *str = lua_tostring(luastate, argc);
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

void LuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaPushStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

/** \internal
 *  \brief fill lua stack with payload
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: payload (string)
 */
static int LuaCallbackStreamingBufferPushToStack(lua_State *luastate, const LuaStreamingBuffer *b)
{
    //PrintRawDataFp(stdout, (uint8_t *)b->data, b->data_len);
    lua_pushlstring (luastate, (const char *)b->data, b->data_len);
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_OPEN));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_CLOSE));
    return 3;
}

/** \internal
 *  \brief Wrapper for getting payload into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackStreamingBuffer(lua_State *luastate)
{
    const LuaStreamingBuffer *b = LuaStateGetStreamingBuffer(luastate);
    if (b == NULL)
        return LuaCallbackError(luastate, "internal error: no buffer");

    return LuaCallbackStreamingBufferPushToStack(luastate, b);
}

/** \internal
 *  \brief fill lua stack with payload
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: payload (string)
 */
static int LuaCallbackPacketPayloadPushToStackFromPacket(lua_State *luastate, const Packet *p)
{
    lua_pushlstring (luastate, (const char *)p->payload, p->payload_len);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting payload into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackPacketPayload(lua_State *luastate)
{
    const Packet *p = LuaStateGetPacket(luastate);
    if (p == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackPacketPayloadPushToStackFromPacket(luastate, p);
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ts (string)
 */
static int LuaCallbackTimeStringPushToStackFromPacket(lua_State *luastate, const Packet *p)
{
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));
    lua_pushstring (luastate, timebuf);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackPacketTimeString(lua_State *luastate)
{
    const Packet *p = LuaStateGetPacket(luastate);
    if (p == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackTimeStringPushToStackFromPacket(luastate, p);
}

/** \internal
 *  \brief fill lua stack with time string
 *  \param luastate the lua state
 *  \param flow flow
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ts (string)
 */
static int LuaCallbackTimeStringPushToStackFromFlow(lua_State *luastate, const Flow *flow)
{
    char timebuf[64];
    CreateTimeString(&flow->startts, timebuf, sizeof(timebuf));
    lua_pushstring (luastate, timebuf);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting ts info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackFlowTimeString(lua_State *luastate)
{
    int r = 0;
    int locked = 0;
    Flow *flow = LuaStateGetFlow(luastate, &locked);
    if (flow == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (locked == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(flow);
        r = LuaCallbackTimeStringPushToStackFromFlow(luastate, flow);
        FLOWLOCK_UNLOCK(flow);
    } else {
        r = LuaCallbackTimeStringPushToStackFromFlow(luastate, flow);
    }
    return r;
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ipver (number), src ip (string), dst ip (string), protocol (number),
 *          sp or icmp type (number), dp or icmp code (number).
 */
static int LuaCallbackTuplePushToStackFromPacket(lua_State *luastate, const Packet *p)
{
    int ipver = 0;
    if (PKT_IS_IPV4(p)) {
        ipver = 4;
    } else if (PKT_IS_IPV6(p)) {
        ipver = 6;
    }
    lua_pushnumber (luastate, ipver);
    if (ipver == 0)
        return 1;

    char srcip[46] = "", dstip[46] = "";
    if (PKT_IS_IPV4(p)) {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    } else if (PKT_IS_IPV6(p)) {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }

    lua_pushstring (luastate, srcip);
    lua_pushstring (luastate, dstip);

    /* proto and ports (or type/code) */
    lua_pushnumber (luastate, p->proto);
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
        lua_pushnumber (luastate, p->sp);
        lua_pushnumber (luastate, p->dp);

    } else if (p->proto == IPPROTO_ICMP || p->proto == IPPROTO_ICMPV6) {
        lua_pushnumber (luastate, p->type);
        lua_pushnumber (luastate, p->code);
    } else {
        lua_pushnumber (luastate, 0);
        lua_pushnumber (luastate, 0);
    }

    return 6;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackTuple(lua_State *luastate)
{
    const Packet *p = LuaStateGetPacket(luastate);
    if (p == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackTuplePushToStackFromPacket(luastate, p);
}

/** \internal
 *  \brief fill lua stack with header info
 *  \param luastate the lua state
 *  \param f flow, locked
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ipver (number), src ip (string), dst ip (string), protocol (number),
 *          sp or icmp type (number), dp or icmp code (number).
 */
static int LuaCallbackTuplePushToStackFromFlow(lua_State *luastate, const Flow *f)
{
    int ipver = 0;
    if (FLOW_IS_IPV4(f)) {
        ipver = 4;
    } else if (FLOW_IS_IPV6(f)) {
        ipver = 6;
    }
    lua_pushnumber (luastate, ipver);
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

    lua_pushstring (luastate, srcip);
    lua_pushstring (luastate, dstip);

    /* proto and ports (or type/code) */
    lua_pushnumber (luastate, f->proto);
    if (f->proto == IPPROTO_TCP || f->proto == IPPROTO_UDP) {
        lua_pushnumber (luastate, f->sp);
        lua_pushnumber (luastate, f->dp);

    } else if (f->proto == IPPROTO_ICMP || f->proto == IPPROTO_ICMPV6) {
        lua_pushnumber (luastate, f->type);
        lua_pushnumber (luastate, f->code);
    } else {
        lua_pushnumber (luastate, 0);
        lua_pushnumber (luastate, 0);
    }

    return 6;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackTupleFlow(lua_State *luastate)
{
    int r = 0;
    int lock_hint = 0;
    Flow *f = LuaStateGetFlow(luastate, &lock_hint);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(f);
        r = LuaCallbackTuplePushToStackFromFlow(luastate, f);
        FLOWLOCK_UNLOCK(f);
    } else {
        r = LuaCallbackTuplePushToStackFromFlow(luastate, f);
    }
    return r;
}

/** \internal
 *  \brief fill lua stack with AppLayerProto
 *  \param luastate the lua state
 *  \param f flow, locked
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: alproto as string (string)
 */
static int LuaCallbackAppLayerProtoPushToStackFromFlow(lua_State *luastate, const Flow *f)
{
    const char *string = AppProtoToString(f->alproto);
    if (string == NULL)
        string = "unknown";
    lua_pushstring(luastate, string);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting AppLayerProto info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackAppLayerProtoFlow(lua_State *luastate)
{
    int r = 0;
    int lock_hint = 0;
    Flow *f = LuaStateGetFlow(luastate, &lock_hint);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(f);
        r = LuaCallbackAppLayerProtoPushToStackFromFlow(luastate, f);
        FLOWLOCK_UNLOCK(f);
    } else {
        r = LuaCallbackAppLayerProtoPushToStackFromFlow(luastate, f);
    }
    return r;
}

/** \internal
 *  \brief fill lua stack with flow stats
 *  \param luastate the lua state
 *  \param f flow, locked
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: ts pkts (number), ts bytes (number), tc pkts (number), tc bytes (number)
 */
static int LuaCallbackStatsPushToStackFromFlow(lua_State *luastate, const Flow *f)
{
    lua_pushnumber(luastate, f->todstpktcnt);
    lua_pushnumber(luastate, f->todstbytecnt);
    lua_pushnumber(luastate, f->tosrcpktcnt);
    lua_pushnumber(luastate, f->tosrcbytecnt);
    return 4;
}

/** \internal
 *  \brief Wrapper for getting AppLayerProto info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackStatsFlow(lua_State *luastate)
{
    int r = 0;
    int lock_hint = 0;
    Flow *f = LuaStateGetFlow(luastate, &lock_hint);
    if (f == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(f);
        r = LuaCallbackStatsPushToStackFromFlow(luastate, f);
        FLOWLOCK_UNLOCK(f);
    } else {
        r = LuaCallbackStatsPushToStackFromFlow(luastate, f);
    }
    return r;
}

/** \internal
 *  \brief fill lua stack with alert info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: sid (number), rev (number), gid (number)
 */
static int LuaCallbackRuleIdsPushToStackFromPacketAlert(lua_State *luastate, const PacketAlert *pa)
{
    lua_pushnumber (luastate, pa->s->id);
    lua_pushnumber (luastate, pa->s->rev);
    lua_pushnumber (luastate, pa->s->gid);
    return 3;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackRuleIds(lua_State *luastate)
{
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackRuleIdsPushToStackFromPacketAlert(luastate, pa);
}

/** \internal
 *  \brief fill lua stack with alert info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: msg (string)
 */
static int LuaCallbackRuleMsgPushToStackFromPacketAlert(lua_State *luastate, const PacketAlert *pa)
{
    lua_pushstring (luastate, pa->s->msg);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackRuleMsg(lua_State *luastate)
{
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackRuleMsgPushToStackFromPacketAlert(luastate, pa);
}

/** \internal
 *  \brief fill lua stack with alert info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: class (string), prio (number)
 */
static int LuaCallbackRuleClassPushToStackFromPacketAlert(lua_State *luastate, const PacketAlert *pa)
{
    lua_pushstring (luastate, pa->s->class_msg);
    lua_pushnumber (luastate, pa->s->prio);
    return 2;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackRuleClass(lua_State *luastate)
{
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa == NULL)
        return LuaCallbackError(luastate, "internal error: no packet");

    return LuaCallbackRuleClassPushToStackFromPacketAlert(luastate, pa);
}

static int LuaCallbackLogPath(lua_State *luastate)
{
    const char *ld = ConfigGetLogDirectory();
    if (ld == NULL)
        return LuaCallbackError(luastate, "internal error: no log dir");

    return LuaPushStringBuffer(luastate, (const uint8_t *)ld, strlen(ld));
}

static int LuaCallbackLogDebug(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogDebug("%s", msg);
    return 0;
}

static int LuaCallbackLogInfo(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogInfo("%s", msg);
    return 0;
}

static int LuaCallbackLogNotice(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogNotice("%s", msg);
    return 0;
}

static int LuaCallbackLogWarning(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogWarning(SC_WARN_LUA_SCRIPT, "%s", msg);
    return 0;
}

static int LuaCallbackLogError(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogError(SC_ERR_LUA_SCRIPT, "%s", msg);
    return 0;
}

/** \internal
 *  \brief fill lua stack with file info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: fileid (number), txid (number), name (string),
 *          size (number), magic (string), md5 in hex (string)
 */
static int LuaCallbackFileInfoPushToStackFromFile(lua_State *luastate, const File *file)
{
#ifdef HAVE_NSS
    char md5[33] = "";
    char *md5ptr = md5;
    if (file->flags & FILE_MD5) {
        size_t x;
        for (x = 0; x < sizeof(file->md5); x++) {
            char one[3] = "";
            snprintf(one, sizeof(one), "%02x", file->md5[x]);
            strlcat(md5, one, sizeof(md5));
        }
    }
#else
    char *md5ptr = NULL;
#endif

    lua_pushnumber(luastate, file->file_id);
    lua_pushnumber(luastate, file->txid);
    lua_pushlstring(luastate, (char *)file->name, file->name_len);
    lua_pushnumber(luastate, file->size);
    lua_pushstring (luastate, file->magic);
    lua_pushstring(luastate, md5ptr);
    return 6;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackFileInfo(lua_State *luastate)
{
    const File *file = LuaStateGetFile(luastate);
    if (file == NULL)
        return LuaCallbackError(luastate, "internal error: no file");

    return LuaCallbackFileInfoPushToStackFromFile(luastate, file);
}

/** \internal
 *  \brief fill lua stack with file info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: state (string), stored (bool)
 */
static int LuaCallbackFileStatePushToStackFromFile(lua_State *luastate, const File *file)
{
    const char *state = "UNKNOWN";
    switch (file->state) {
        case FILE_STATE_CLOSED:
            state = "CLOSED";
            break;
        case FILE_STATE_TRUNCATED:
            state = "TRUNCATED";
            break;
        case FILE_STATE_ERROR:
            state = "ERROR";
            break;
    }

    lua_pushstring (luastate, state);
    lua_pushboolean (luastate, file->flags & FILE_STORED);
    return 2;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackFileState(lua_State *luastate)
{
    const File *file = LuaStateGetFile(luastate);
    if (file == NULL)
        return LuaCallbackError(luastate, "internal error: no file");

    return LuaCallbackFileStatePushToStackFromFile(luastate, file);
}

/** \internal
 *  \brief fill lua stack with thread info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: thread id (number), thread name (string, thread group name (string)
 */
static int LuaCallbackThreadInfoPushToStackFromThreadVars(lua_State *luastate, const ThreadVars *tv)
{
    u_long tid = SCGetThreadIdLong();
    lua_pushinteger (luastate, (lua_Integer)tid);
    lua_pushstring (luastate, tv->name);
    lua_pushstring (luastate, tv->thread_group_name);
    return 3;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackThreadInfo(lua_State *luastate)
{
    const ThreadVars *tv = LuaStateGetThreadVars(luastate);
    if (tv == NULL)
        return LuaCallbackError(luastate, "internal error: no tv");

    return LuaCallbackThreadInfoPushToStackFromThreadVars(luastate, tv);
}

int LuaRegisterFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, LuaCallbackPacketPayload);
    lua_setglobal(luastate, "SCPacketPayload");
    lua_pushcfunction(luastate, LuaCallbackPacketTimeString);
    lua_setglobal(luastate, "SCPacketTimeString");
    lua_pushcfunction(luastate, LuaCallbackTuple);
    lua_setglobal(luastate, "SCPacketTuple");

    lua_pushcfunction(luastate, LuaCallbackFlowTimeString);
    lua_setglobal(luastate, "SCFlowTimeString");
    lua_pushcfunction(luastate, LuaCallbackTupleFlow);
    lua_setglobal(luastate, "SCFlowTuple");
    lua_pushcfunction(luastate, LuaCallbackAppLayerProtoFlow);
    lua_setglobal(luastate, "SCFlowAppLayerProto");
    lua_pushcfunction(luastate, LuaCallbackStatsFlow);
    lua_setglobal(luastate, "SCFlowStats");

    lua_pushcfunction(luastate, LuaCallbackStreamingBuffer);
    lua_setglobal(luastate, "SCStreamingBuffer");

    lua_pushcfunction(luastate, LuaCallbackLogPath);
    lua_setglobal(luastate, "SCLogPath");

    lua_pushcfunction(luastate, LuaCallbackLogDebug);
    lua_setglobal(luastate, "SCLogDebug");
    lua_pushcfunction(luastate, LuaCallbackLogInfo);
    lua_setglobal(luastate, "SCLogInfo");
    lua_pushcfunction(luastate, LuaCallbackLogNotice);
    lua_setglobal(luastate, "SCLogNotice");
    lua_pushcfunction(luastate, LuaCallbackLogWarning);
    lua_setglobal(luastate, "SCLogWarning");
    lua_pushcfunction(luastate, LuaCallbackLogError);
    lua_setglobal(luastate, "SCLogError");


    lua_pushcfunction(luastate, LuaCallbackRuleIds);
    lua_setglobal(luastate, "SCRuleIds");
    lua_pushcfunction(luastate, LuaCallbackRuleMsg);
    lua_setglobal(luastate, "SCRuleMsg");
    lua_pushcfunction(luastate, LuaCallbackRuleClass);
    lua_setglobal(luastate, "SCRuleClass");

    lua_pushcfunction(luastate, LuaCallbackFileInfo);
    lua_setglobal(luastate, "SCFileInfo");
    lua_pushcfunction(luastate, LuaCallbackFileState);
    lua_setglobal(luastate, "SCFileState");

    lua_pushcfunction(luastate, LuaCallbackThreadInfo);
    lua_setglobal(luastate, "SCThreadInfo");
    return 0;
}

int LuaStateNeedProto(lua_State *luastate, AppProto alproto)
{
    AppProto flow_alproto = 0;
    int locked = 0;
    Flow *flow = LuaStateGetFlow(luastate, &locked);
    if (flow == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    if (locked == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(flow);
        flow_alproto = flow->alproto;
        FLOWLOCK_UNLOCK(flow);
    } else {
        flow_alproto = flow->alproto;
    }

    return (alproto == flow_alproto);

}

#endif /* HAVE_LUA */
