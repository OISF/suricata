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
#include "rust.h"
#include "util-lua-base64lib.h"
#include "util-validate.h"

#include "lauxlib.h"

static int LuaBase64EncodeStandard(lua_State *L)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    size_t out_len = SCBase64EncodeBufferSize(input_len);
    char output[out_len + 1];
    if (SCBase64Encode((uint8_t *)input, (unsigned long)input_len, (u_char *)output,
                (unsigned long *)&out_len) != 0) {
        return luaL_error(L, "base64 encoding failed");
    }
    lua_pushstring(L, (const char *)output);

    return 1;
}

static int LuaBase64EncodeStandardNoPad(lua_State *L)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    size_t out_len = SCBase64EncodeBufferSize(input_len);
    char output[out_len + 1];
    if (SCBase64EncodeNoPad((uint8_t *)input, (unsigned long)input_len, (u_char *)output,
                (unsigned long *)&out_len) != 0) {
        return luaL_error(L, "base64 encoding failed");
    }
    lua_pushstring(L, (const char *)output);

    return 1;
}

static int LuaBase64DecodeStandard(lua_State *L)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    char output[input_len];
    uint32_t n = SCBase64Decode(
            (uint8_t *)input, (uintptr_t)input_len, SCBase64ModeStrict, (uint8_t *)output);
    if (n == 0) {
        return luaL_error(L, "base64 decoding failed");
    }
    DEBUG_VALIDATE_BUG_ON(n > input_len);
    output[n] = '\0';
    lua_pushstring(L, (const char *)output);

    return 1;
}

static int LuaBase64DecodeStandardNoPad(lua_State *L)
{
    size_t input_len;
    const char *input = luaL_checklstring(L, 1, &input_len);
    char output[input_len];
    uint32_t n = SCBase64Decode(
            (uint8_t *)input, (uintptr_t)input_len, SCBase64ModeNoPad, (uint8_t *)output);
    if (n == 0) {
        return luaL_error(L, "base64 decoding failed");
    }
    DEBUG_VALIDATE_BUG_ON(n > input_len);
    output[n] = '\0';
    lua_pushstring(L, (const char *)output);

    return 1;
}

static const struct luaL_Reg base64lib[] = {
    // clang-format off
    { "encode", LuaBase64EncodeStandard },
    { "encode_nopad", LuaBase64EncodeStandardNoPad },
    { "decode", LuaBase64DecodeStandard },
    { "decode_nopad", LuaBase64DecodeStandardNoPad },
    { NULL, NULL },
    // clang-format on
};

int SCLuaLoadBase64Lib(lua_State *L)
{
    luaL_newlib(L, base64lib);

    return 1;
}
