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
 * Configuration API for Lua.
 *
 * local config = require("suricata.config")
 */

#include "suricata-common.h"
#include "util-lua-config.h"
#include "conf.h"
#include "util-conf.h"
#include "app-layer-protos.h"
#include "util-lua-common.h"
#include "util-lua.h"

#include "lauxlib.h"

static int LuaConfigLogPath(lua_State *L)
{
    const char *ld = SCConfigGetLogDirectory();
    if (ld == NULL)
        return LuaCallbackError(L, "internal error: no log dir");

    return LuaPushStringBuffer(L, (const uint8_t *)ld, strlen(ld));
}

static const luaL_Reg configlib[] = {
    // clang-format off
    { "log_path", LuaConfigLogPath },
    { NULL, NULL },
    // clang-format on
};

int SCLuaLoadConfigLib(lua_State *L)
{
    luaL_newlib(L, configlib);
    return 1;
}
