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

#include "suricata-common.h"
#include "action-globals.h"
#include "app-layer.h"
#include "util-lua-rule.h"
#include "util-lua-common.h"
#include "util-lua.h"

#include "lauxlib.h"

static const char suricata_rule_mt[] = "suricata:rule:mt";

/*
 * The handle is a value copy, not a pointer: the Signature it came from
 * is engine-owned and freed on rule reload (SigFree) while output states
 * keep running, so a cached pointer handle would dangle.
 */
typedef struct LuaRuleData_ {
    uint32_t sid;
    uint32_t gid;
    uint32_t rev;
    uint8_t action;
    int prio;
    /* point into the same userdata, behind the struct: allocated and
     * counted by the Lua allocator and freed with the handle, so there
     * is no finalizer a script could remove */
    const char *msg;
    const char *class_msg;
} LuaRuleData;

static int LuaRuleGetRule(lua_State *L)
{
    const PacketAlert *pa = LuaStateGetPacketAlert(L);
    const Signature *s = NULL;
    if (pa != NULL) {
        s = pa->s;
    } else {
        s = LuaStateGetSignature(L);
    }
    if (s == NULL) {
        return LuaCallbackError(L, "internal error: no packet alert or signature");
    }

    const size_t msg_size = s->msg ? strlen(s->msg) + 1 : 0;
    const size_t class_size = s->class_msg ? strlen(s->class_msg) + 1 : 0;
    LuaRuleData *r = (LuaRuleData *)lua_newuserdata(L, sizeof(*r) + msg_size + class_size);
    if (r == NULL) {
        return LuaCallbackError(L, "error: failed to allocate user data");
    }
    r->sid = s->id;
    r->gid = s->gid;
    r->rev = s->rev;
    r->action = s->action;
    r->prio = s->prio;
    char *strs = (char *)(r + 1);
    r->msg = NULL;
    if (msg_size > 0) {
        memcpy(strs, s->msg, msg_size);
        r->msg = strs;
        strs += msg_size;
    }
    r->class_msg = NULL;
    if (class_size > 0) {
        memcpy(strs, s->class_msg, class_size);
        r->class_msg = strs;
    }

    luaL_getmetatable(L, suricata_rule_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaRuleGetSid(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, r->sid);
    return 1;
}

static int LuaRuleGetGid(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, r->gid);
    return 1;
}

static int LuaRuleGetRev(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, r->rev);
    return 1;
}

static int LuaRuleGetAction(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }

    const char *action = "";
    if (r->action & ACTION_PASS) {
        action = "pass";
    } else if ((r->action & ACTION_REJECT) || (r->action & ACTION_REJECT_BOTH) ||
               (r->action & ACTION_REJECT_DST)) {
        action = "reject";
    } else if (r->action & ACTION_DROP) {
        action = "drop";
    } else if (r->action & ACTION_ALERT) {
        action = "alert";
    }
    lua_pushstring(L, action);
    return 1;
}

static int LuaRuleGetMsg(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushstring(L, r->msg ? r->msg : "");
    return 1;
}

static int LuaRuleGetClassDescription(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushstring(L, r->class_msg ? r->class_msg : "");
    return 1;
}

static int LuaRuleGetPriority(lua_State *L)
{
    LuaRuleData *r = luaL_testudata(L, 1, suricata_rule_mt);
    if (r == NULL) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, r->prio);
    return 1;
}

static const struct luaL_Reg rulemt[] = {
    // clang-format off
    { "action", LuaRuleGetAction },
    { "class_description", LuaRuleGetClassDescription, },
    { "gid", LuaRuleGetGid, },
    { "msg", LuaRuleGetMsg },
    { "priority", LuaRuleGetPriority },
    { "rev", LuaRuleGetRev, },
    { "sid", LuaRuleGetSid, },
    { NULL, NULL },
    // clang-format on
};

static const struct luaL_Reg rulelib[] = {
    // clang-format off
    { "get_rule", LuaRuleGetRule, },
    { NULL, NULL, }
    // clang-format on
};

int SCLuaLoadRuleLib(lua_State *L)
{
    luaL_newmetatable(L, suricata_rule_mt);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, rulemt, 0);

    luaL_newlib(L, rulelib);

    return 1;
}
