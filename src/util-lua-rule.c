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

    void **p = lua_newuserdata(L, sizeof(*p));
    if (p == NULL) {
        return LuaCallbackError(L, "error: failed to allocate user data");
    }
    *p = (void *)s;

    luaL_getmetatable(L, suricata_rule_mt);
    lua_setmetatable(L, -2);

    return 1;
}

static int LuaRuleGetSid(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushinteger(L, s->id);
    return 1;
}

static int LuaRuleGetGid(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushinteger(L, s->gid);
    return 1;
}

static int LuaRuleGetRev(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushinteger(L, s->rev);
    return 1;
}

static int LuaRuleGetAction(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;

    const char *action = "";
    if (s->action & ACTION_PASS) {
        action = "pass";
    } else if ((s->action & ACTION_REJECT) || (s->action & ACTION_REJECT_BOTH) ||
               (s->action & ACTION_REJECT_DST)) {
        action = "reject";
    } else if (s->action & ACTION_DROP) {
        action = "drop";
    } else if (s->action & ACTION_ALERT) {
        action = "alert";
    }
    lua_pushstring(L, action);
    return 1;
}

static int LuaRuleGetMsg(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushstring(L, s->msg);
    return 1;
}

static int LuaRuleGetClassDescription(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushstring(L, s->class_msg);
    return 1;
}

static int LuaRuleGetPriority(lua_State *L)
{
    void **data = luaL_testudata(L, 1, suricata_rule_mt);
    if (data == NULL) {
        lua_pushnil(L);
        return 1;
    }
    const Signature *s = *data;
    lua_pushinteger(L, s->prio);
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
