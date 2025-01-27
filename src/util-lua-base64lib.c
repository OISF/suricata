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
#include "util-lua-base64lib.h"
#include "util-validate.h"
#include "lauxlib.h"
#include "rust.h"

static int LuaBase64Encode(lua_State *L, SCBase64Mode mode)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    size_t out_len = SCBase64EncodeBufferSize(input_len);
    char *output = SCCalloc(out_len + 1, sizeof(char));
    if (output == NULL) {
        return luaL_error(L, "malloc");
    }
    if (SCBase64EncodeWithMode((uint8_t *)input, (unsigned long)input_len, (u_char *)output,
                (unsigned long *)&out_len, mode) != 0) {
        SCFree(output);
        return luaL_error(L, "base64 encoding failed");
    }
    lua_pushstring(L, (const char *)output);
    SCFree(output);

    return 1;
}

static int LuaBase64EncodeStandard(lua_State *L)
{
    return LuaBase64Encode(L, SCBase64ModeStrict);
}

static int LuaBase64EncodeStandardNoPad(lua_State *L)
{
    return LuaBase64Encode(L, SCBase64ModeNoPad);
}

static int LuaBase64Decode(lua_State *L, SCBase64Mode mode)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    char *output = SCCalloc(input_len, sizeof(char));
    if (output == NULL) {
        return luaL_error(L, "malloc");
    }
    uint32_t n = SCBase64Decode((uint8_t *)input, (uintptr_t)input_len, mode, (uint8_t *)output);
    if (n == 0) {
        SCFree(output);
        return luaL_error(L, "base64 decoding failed");
    }
    DEBUG_VALIDATE_BUG_ON(n > input_len);
    output[n] = '\0';
    lua_pushstring(L, (const char *)output);
    SCFree(output);

    return 1;
}

static int LuaBase64DecodeStandard(lua_State *L)
{
    return LuaBase64Decode(L, SCBase64ModeStrict);
}

static int LuaBase64DecodeStandardNoPad(lua_State *L)
{
    return LuaBase64Decode(L, SCBase64ModeNoPad);
}

static int LuaBase64DecodeStandardPadOpt(lua_State *L)
{
    return LuaBase64Decode(L, SCBase64ModePadOpt);
}

static int LuaBase64DecodeRFC2045(lua_State *L)
{
    return LuaBase64Decode(L, SCBase64ModeRFC2045);
}

static int LuaBase64DecodeRFC4648(lua_State *L)
{
    return LuaBase64Decode(L, SCBase64ModeRFC4648);
}

static const struct luaL_Reg base64lib[] = {
    // clang-format off
    { "encode", LuaBase64EncodeStandard },
    { "encode_nopad", LuaBase64EncodeStandardNoPad },
    { "decode", LuaBase64DecodeStandard },
    { "decode_nopad", LuaBase64DecodeStandardNoPad },
    { "decode_padopt", LuaBase64DecodeStandardPadOpt },
    { "decode_rfc2045", LuaBase64DecodeRFC2045 },
    { "decode_rfc4648", LuaBase64DecodeRFC4648 },
    { NULL, NULL },
    // clang-format on
};

int SCLuaLoadBase64Lib(lua_State *L)
{
    luaL_newlib(L, base64lib);

    return 1;
}
