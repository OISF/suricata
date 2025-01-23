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
#include "util-lua-builtins.h"
#include "util-lua-hashlib.h"
#include "util-lua-dataset.h"

#include "lauxlib.h"

static const luaL_Reg builtins[] = {
    { "suricata.hashlib", SCLuaLoadHashlib },
    { "suricata.dataset", LuaLoadDatasetLib },
    { NULL, NULL },
};

/**
 * \brief Load a Suricata built-in module in a sand-boxed environment.
 */
bool SCLuaLoadBuiltIns(lua_State *L, const char *name)
{
    for (const luaL_Reg *lib = builtins; lib->name; lib++) {
        if (strcmp(name, lib->name) == 0) {
            lib->func(L);
            return true;
        }
    }
    return false;
}

/**
 * \brief Register Suricata built-in modules for loading in a
 *     non-sandboxed environment.
 */
void SCLuaRequirefBuiltIns(lua_State *L)
{
    for (const luaL_Reg *lib = builtins; lib->name; lib++) {
        luaL_requiref(L, lib->name, lib->func, 0);
        lua_pop(L, 1);
    }
}
