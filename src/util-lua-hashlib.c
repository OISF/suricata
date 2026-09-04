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
 * Hashing library for Lua.
 *
 * Usage:
 *
 * local hashing = require("suricata.hashing")
 *
 * -- One shot hash
 * hash = hashing.sha256_digest("www.suricata.io")
 *
 * -- One shot hash to hex
 * hash = hashing.sha256_hexdigest("www.suricata.io")
 *
 * -- Incremental hashing
 * hasher = hashing.sha256()
 * hasher:update("www.")
 * hasher:update("suricata.io")
 * hash = hasher:finalize()
 *
 * Support hashes: sha256, sha1, md5
 */

#include "util-lua-hashlib.h"

#include "lauxlib.h"
#include "rust-bindings.h"

#define SHA256_MT "suricata:hashlib:sha256"
#define SHA1_MT   "suricata:hashlib:sha1"
#define MD5_MT    "suricata:hashlib:md5"

/**
 * \brief Create a new SHA-256 hash instance.
 */
static int LuaHashLibSha256New(lua_State *L)
{
    struct SCSha256 **hasher = lua_newuserdata(L, sizeof(struct SCSha256 *));
    if (hasher == NULL) {
        return luaL_error(L, "failed to allocate userdata for sha256");
    }
    *hasher = SCSha256New();
    luaL_getmetatable(L, SHA256_MT);
    lua_setmetatable(L, -2);
    return 1;
}

/**
 * \brief Add more data to an existing SHA-256 hash instance.
 */
static int LuaHashLibSha256Update(lua_State *L)
{
    struct SCSha256 **hasher = luaL_checkudata(L, 1, SHA256_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha256 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha256 hasher already finalized");
    }
    size_t data_len;
    const char *data = luaL_checklstring(L, 2, &data_len);
    SCSha256Update(*hasher, (const uint8_t *)data, (uint32_t)data_len);
    return 0;
}

static int LuaHashLibSha256Finalize(lua_State *L)
{
    struct SCSha256 **hasher = luaL_checkudata(L, 1, SHA256_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha256 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha256 hasher already finalized");
    }

    uint8_t hash[SC_SHA256_LEN];
    struct SCSha256 *ctx = *hasher;
    *hasher = NULL;
    SCSha256Finalize(ctx, hash, sizeof(hash));
    lua_pushlstring(L, (const char *)hash, sizeof(hash));

    return 1;
}

static int LuaHashLibSha256FinalizeToHex(lua_State *L)
{
    struct SCSha256 **hasher = luaL_checkudata(L, 1, SHA256_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha256 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha256 hasher already finalized");
    }

    char hash[SC_SHA256_HEX_LEN + 1];
    struct SCSha256 *ctx = *hasher;
    *hasher = NULL;
    if (!SCSha256FinalizeToHex(ctx, hash, sizeof(hash))) {
        return luaL_error(L, "sha256 hashing failed");
    }

    lua_pushstring(L, (const char *)hash);

    return 1;
}

static int LuaHashLibSha256Digest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    uint32_t output_len = SC_SHA256_LEN;
    uint8_t output[output_len];
    if (!SCSha256HashBuffer((uint8_t *)input, (uint32_t)buf_len, output, output_len)) {
        return luaL_error(L, "sha256 hashing failed");
    }

    lua_pushlstring(L, (const char *)output, output_len);

    return 1;
}

static int LuaHashLibSha256HexDigest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    char output[SC_SHA256_HEX_LEN + 1];
    if (!SCSha256HashBufferToHex((uint8_t *)input, (uint32_t)buf_len, output, sizeof(output))) {
        return luaL_error(L, "sha256 hashing failed");
    }

    lua_pushstring(L, (const char *)output);
    return 1;
}

static int LuaHashLibSha256Gc(lua_State *L)
{
    struct SCSha256 **hasher = luaL_checkudata(L, 1, SHA256_MT);
    if (hasher && *hasher) {
        struct SCSha256 *ctx = *hasher;
        *hasher = NULL;
        SCSha256Free(ctx);
    }
    return 0;
}

static int LuaHashLibSha1New(lua_State *L)
{
    struct SCSha1 **hasher = lua_newuserdata(L, sizeof(struct SCSha1 *));
    if (hasher == NULL) {
        return luaL_error(L, "failed to allocate userdata for sha1");
    }
    *hasher = SCSha1New();
    luaL_getmetatable(L, SHA1_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static int LuaHashLibSha1Update(lua_State *L)
{
    struct SCSha1 **hasher = luaL_checkudata(L, 1, SHA1_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha1 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha1 hasher already finalized");
    }

    size_t data_len;
    const char *data = luaL_checklstring(L, 2, &data_len);
    SCSha1Update(*hasher, (const uint8_t *)data, (uint32_t)data_len);
    return 0;
}

static int LuaHashLibSha1Finalize(lua_State *L)
{
    struct SCSha1 **hasher = luaL_checkudata(L, 1, SHA1_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha1 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha1 hasher already finalized");
    }

    uint8_t hash[SC_SHA1_LEN];
    struct SCSha1 *ctx = *hasher;
    *hasher = NULL;
    SCSha1Finalize(ctx, hash, sizeof(hash));
    lua_pushlstring(L, (const char *)hash, sizeof(hash));

    return 1;
}

static int LuaHashLibSha1FinalizeToHex(lua_State *L)
{
    struct SCSha1 **hasher = luaL_checkudata(L, 1, SHA1_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid sha1 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "sha1 hasher already finalized");
    }

    char hash[SC_SHA1_HEX_LEN + 1];
    struct SCSha1 *ctx = *hasher;
    *hasher = NULL;
    if (!SCSha1FinalizeToHex(ctx, hash, sizeof(hash))) {
        return luaL_error(L, "sha1 hashing failed");
    }

    lua_pushstring(L, (const char *)hash);

    return 1;
}

static int LuaHashLibSha1Digest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    uint8_t output[SC_SHA1_LEN];
    if (!SCSha1HashBuffer((uint8_t *)input, (uint32_t)buf_len, output, sizeof(output))) {
        return luaL_error(L, "sha1 hashing failed");
    }

    lua_pushlstring(L, (const char *)output, sizeof(output));
    return 1;
}

static int LuaHashLibSha1HexDigest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    char output[SC_SHA1_HEX_LEN + 1];
    if (!SCSha1HashBufferToHex((uint8_t *)input, (uint32_t)buf_len, output, sizeof(output))) {
        return luaL_error(L, "sha1 hashing failed");
    }

    lua_pushstring(L, (const char *)output);
    return 1;
}

static int LuaHashLibSha1Gc(lua_State *L)
{
    struct SCSha1 **hasher = luaL_checkudata(L, 1, SHA1_MT);
    if (hasher && *hasher) {
        struct SCSha1 *ctx = *hasher;
        *hasher = NULL;
        SCSha1Free(ctx);
    }
    return 0;
}

static int LuaHashLibMd5New(lua_State *L)
{
    struct SCMd5 **hasher = lua_newuserdata(L, sizeof(struct SCMd5 *));
    if (hasher == NULL) {
        return luaL_error(L, "failed to allocate userdata for sha1");
    }
    *hasher = SCMd5New();
    luaL_getmetatable(L, MD5_MT);
    lua_setmetatable(L, -2);
    return 1;
}

static int LuaHashLibMd5Update(lua_State *L)
{
    struct SCMd5 **hasher = luaL_checkudata(L, 1, MD5_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid md5 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "md5 hasher already finalized");
    }

    size_t data_len;
    const char *data = luaL_checklstring(L, 2, &data_len);
    SCMd5Update(*hasher, (const uint8_t *)data, (uint32_t)data_len);
    return 0;
}

static int LuaHashLibMd5Finalize(lua_State *L)
{
    struct SCMd5 **hasher = luaL_checkudata(L, 1, MD5_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid md5 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "md5 hasher already finalized");
    }

    uint8_t hash[SC_MD5_LEN];
    struct SCMd5 *ctx = *hasher;
    *hasher = NULL;
    SCMd5Finalize(ctx, hash, sizeof(hash));
    lua_pushlstring(L, (const char *)hash, sizeof(hash));

    return 1;
}

static int LuaHashLibMd5FinalizeToHex(lua_State *L)
{
    struct SCMd5 **hasher = luaL_checkudata(L, 1, MD5_MT);
    if (hasher == NULL || *hasher == NULL) {
        return luaL_error(L, "invalid md5 hash context");
    }
    if (*hasher == NULL) {
        return luaL_error(L, "md5 hasher already finalized");
    }

    char hash[SC_MD5_HEX_LEN + 1];
    struct SCMd5 *ctx = *hasher;
    *hasher = NULL;
    if (!SCMd5FinalizeToHex(ctx, hash, sizeof(hash))) {
        return luaL_error(L, "md5 hashing failed");
    }

    lua_pushstring(L, (const char *)hash);

    return 1;
}

static int LuaHashLibMd5Digest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    uint8_t output[SC_MD5_LEN];
    if (!SCMd5HashBuffer((uint8_t *)input, (uint32_t)buf_len, output, sizeof(output))) {
        return luaL_error(L, "md5 hashing failed");
    }

    lua_pushlstring(L, (const char *)output, sizeof(output));
    return 1;
}

static int LuaHashLibMd5HexDigest(lua_State *L)
{
    size_t buf_len;
    const char *input = luaL_checklstring(L, 1, &buf_len);

    char output[SC_MD5_HEX_LEN + 1];
    if (!SCMd5HashBufferToHex((uint8_t *)input, (uint32_t)buf_len, output, sizeof(output))) {
        return luaL_error(L, "md5 hashing failed");
    }

    lua_pushstring(L, (const char *)output);
    return 1;
}

static int LuaHashLibMd5Gc(lua_State *L)
{
    struct SCMd5 **hasher = luaL_checkudata(L, 1, MD5_MT);
    if (hasher && *hasher) {
        struct SCMd5 *ctx = *hasher;
        *hasher = NULL;
        SCMd5Free(ctx);
    }
    return 0;
}

static const struct luaL_Reg hashlib[] = {
    // clang-format off
    { "sha256_digest", LuaHashLibSha256Digest },
    { "sha256_hexdigest", LuaHashLibSha256HexDigest },
    { "sha256", LuaHashLibSha256New },
    { "sha1_digest", LuaHashLibSha1Digest },
    { "sha1_hexdigest", LuaHashLibSha1HexDigest },
    { "sha1", LuaHashLibSha1New },
    { "md5_digest", LuaHashLibMd5Digest },
    { "md5_hexdigest", LuaHashLibMd5HexDigest },
    { "md5", LuaHashLibMd5New },
    { NULL, NULL },
    // clang-format on
};

static const struct luaL_Reg sha256_methods[] = {
    // clang-format off
    { "update", LuaHashLibSha256Update },
    { "finalize", LuaHashLibSha256Finalize },
    { "finalize_to_hex", LuaHashLibSha256FinalizeToHex },
    { NULL, NULL },
    // clang-format on
};

static const struct luaL_Reg sha1_methods[] = {
    // clang-format off
    { "update", LuaHashLibSha1Update },
    { "finalize", LuaHashLibSha1Finalize },
    { "finalize_to_hex", LuaHashLibSha1FinalizeToHex },
    { NULL, NULL },
    // clang-format on
};

static const struct luaL_Reg md5_methods[] = {
    // clang-format off
    { "update", LuaHashLibMd5Update },
    { "finalize", LuaHashLibMd5Finalize },
    { "finalize_to_hex", LuaHashLibMd5FinalizeToHex },
    { NULL, NULL },
    // clang-format on
};

int SCLuaLoadHashlib(lua_State *L)
{
    luaL_newmetatable(L, SHA256_MT);
    lua_pushcfunction(L, LuaHashLibSha256Gc);
    lua_setfield(L, -2, "__gc");
    luaL_newlib(L, sha256_methods);
    lua_setfield(L, -2, "__index");

    luaL_newmetatable(L, SHA1_MT);
    lua_pushcfunction(L, LuaHashLibSha1Gc);
    lua_setfield(L, -2, "__gc");
    luaL_newlib(L, sha1_methods);
    lua_setfield(L, -2, "__index");

    luaL_newmetatable(L, MD5_MT);
    lua_pushcfunction(L, LuaHashLibMd5Gc);
    lua_setfield(L, -2, "__gc");
    luaL_newlib(L, md5_methods);
    lua_setfield(L, -2, "__index");

    luaL_newlib(L, hashlib);

    return 1;
}
