/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements the luxaform transform keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-parse.h"
#include "detect-lua.h"
#include "detect-transform-luaxform.h"
#include "detect-lua-extensions.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-builtins.h"

static int DetectTransformLuaxformSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectTransformLuaxformFree(DetectEngineCtx *de_ctx, void *ptr);
static void TransformLuaxform(
        DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer, void *options);

#define LUAXFORM_MAX_ARGS 10

typedef struct DetectLuaxformData {
    int thread_ctx_id;
    int allow_restricted_functions;
    int arg_count;
    uint64_t alloc_limit;
    uint64_t instruction_limit;
    const char *filename;
    char *copystr;
    const char *id_data;
    uint32_t id_data_len;
    const char *args[LUAXFORM_MAX_ARGS];
} DetectLuaxformData;

typedef struct DetectLuaxformThreadData {
    lua_State *luastate;
} DetectLuaxformThreadData;

static void DetectTransformLuaxformId(const uint8_t **data, uint32_t *length, void *context)
{
    if (context) {
        DetectLuaxformData *lua = (DetectLuaxformData *)context;
        *data = (uint8_t *)lua->id_data;
        *length = lua->id_data_len;
    }
}

static void DetectTransformLuaxformFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectLuaxformData *lua = (DetectLuaxformData *)ptr;

        if (lua->filename)
            SCFree((void *)lua->filename);

        if (lua->copystr)
            SCFree((void *)lua->copystr);

        if (lua->id_data)
            SCFree((void *)lua->id_data);

        if (de_ctx) {
            DetectUnregisterThreadCtxFuncs(de_ctx, lua, "luaxform");
        }

        SCFree(lua);
    }
}

static int DetectTransformLuaxformSetupPrime(
        DetectEngineCtx *de_ctx, DetectLuaxformData *ld, const Signature *s)
{
    lua_State *luastate = SCLuaSbStateNew(ld->alloc_limit, ld->instruction_limit);
    if (luastate == NULL)
        return -1;
    if (ld->allow_restricted_functions) {
        luaL_openlibs(luastate);
        SCLuaRequirefBuiltIns(luastate);
    } else {
        SCLuaSbLoadLibs(luastate);
    }

    int status = luaL_loadfile(luastate, ld->filename);
    if (status) {
        SCLogError("couldn't load file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    /* prime the script (or something) */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError("couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "transform");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError("no transform function in script");
        goto error;
    }
    lua_pop(luastate, 1);

    SCLuaSbStateClose(luastate);
    return 0;

error:
    SCLuaSbStateClose(luastate);
    return -1;
}

static DetectLuaxformData *DetectLuaxformParse(DetectEngineCtx *de_ctx, const char *optsstr)
{
    DetectLuaxformData *lua = NULL;

    /* We have a correct lua option */
    lua = SCCalloc(1, sizeof(DetectLuaxformData));
    if (unlikely(lua == NULL)) {
        FatalError("unable to allocate memory for Lua transform: %s", optsstr);
    }

    lua->copystr = strdup(optsstr);
    lua->id_data = strdup(optsstr);
    if (unlikely(lua->copystr == NULL || lua->id_data == NULL)) {
        FatalError("unable to allocate memory for Lua transform: %s", optsstr);
    }

    lua->id_data_len = (uint32_t)strlen(lua->id_data);

    int count = 0;
    char *saveptr = NULL;
    char *token = strtok_r(lua->copystr, ",", &saveptr);
    while (token != NULL && count < LUAXFORM_MAX_ARGS) {
        lua->args[count++] = token;
        token = strtok_r(NULL, ",", &saveptr);
    }

    if (count == 0) {
        SCLogError("Lua script name not supplied");
        goto error;
    }

    lua->arg_count = count - 1;

    /* get full filename */
    lua->filename = DetectLoadCompleteSigPath(de_ctx, lua->args[0]);
    if (lua->filename == NULL) {
        goto error;
    }

    return lua;

error:
    if (lua != NULL)
        DetectTransformLuaxformFree(de_ctx, lua);
    return NULL;
}

static void *DetectLuaxformThreadInit(void *data)
{
    /* Note: This will always be non-null as alloc errors are checked before registering callback */
    DetectLuaxformData *lua = (DetectLuaxformData *)data;

    DetectLuaThreadData *t = SCCalloc(1, sizeof(DetectLuaThreadData));
    if (unlikely(t == NULL)) {
        FatalError("unable to allocate luaxform context memory");
    }

    t->luastate = SCLuaSbStateNew(lua->alloc_limit, lua->instruction_limit);
    if (t->luastate == NULL) {
        SCLogError("luastate pool depleted");
        goto error;
    }

    if (lua->allow_restricted_functions) {
        luaL_openlibs(t->luastate);
        SCLuaRequirefBuiltIns(t->luastate);
    } else {
        SCLuaSbLoadLibs(t->luastate);
    }

    int status = luaL_loadfile(t->luastate, lua->filename);
    if (status) {
        SCLogError("couldn't load file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

    /* prime the script (or something) */
    if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
        SCLogError("couldn't prime file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

    /* when present: thread_init call */
    lua_getglobal(t->luastate, "thread_init");
    if (lua_isfunction(t->luastate, -1)) {
        if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
            SCLogError("couldn't run script 'thread_init' function: %s",
                    lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
        lua_pop(t->luastate, 1);
    }

    return (void *)t;

error:
    if (t->luastate != NULL)
        SCLuaSbStateClose(t->luastate);
    SCFree(t);
    return NULL;
}

static void DetectLuaxformThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectLuaxformThreadData *t = (DetectLuaxformThreadData *)ctx;
        if (t->luastate != NULL)
            SCLuaSbStateClose(t->luastate);
        SCFree(t);
    }
}

/**
 *  \internal
 *  \brief Apply the luaxform keyword to the last pattern match
 *  \param de_ctx detection engine ctx
 *  \param s signature
 *  \param str lua filename and optional args
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectTransformLuaxformSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optsstr)
{
    SCEnter();

    /* First check if Lua rules are enabled, by default Lua in rules
     * is disabled. */
    int enabled = 0;
    (void)SCConfGetBool("security.lua.allow-rules", &enabled);
    if (!enabled) {
        SCLogError("Lua rules disabled by security configuration: security.lua.allow-rules");
        SCReturnInt(-1);
    }

    DetectLuaxformData *lua = DetectLuaxformParse(de_ctx, optsstr);
    if (lua == NULL)
        goto error;

    /* Load lua sandbox configurations */
    intmax_t lua_alloc_limit = DEFAULT_LUA_ALLOC_LIMIT;
    intmax_t lua_instruction_limit = DEFAULT_LUA_INSTRUCTION_LIMIT;
    int allow_restricted_functions = 0;
    (void)SCConfGetInt("security.lua.max-bytes", &lua_alloc_limit);
    (void)SCConfGetInt("security.lua.max-instructions", &lua_instruction_limit);
    (void)SCConfGetBool("security.lua.allow-restricted-functions", &allow_restricted_functions);

    lua->alloc_limit = lua_alloc_limit;
    lua->instruction_limit = lua_instruction_limit;
    lua->allow_restricted_functions = allow_restricted_functions;

    if (DetectTransformLuaxformSetupPrime(de_ctx, lua, s) == -1) {
        goto error;
    }

    lua->thread_ctx_id = DetectRegisterThreadCtxFuncs(
            de_ctx, "luaxform", DetectLuaxformThreadInit, (void *)lua, DetectLuaxformThreadFree, 0);
    if (lua->thread_ctx_id == -1)
        goto error;

    if (0 == SCDetectSignatureAddTransform(s, DETECT_TRANSFORM_LUAXFORM, lua))
        SCReturnInt(0);

error:

    if (lua != NULL)
        DetectTransformLuaxformFree(de_ctx, lua);
    SCReturnInt(-1);
}

static void TransformLuaxform(
        DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer, void *options)
{
    if (buffer->inspect_len == 0) {
        return;
    }

    DetectLuaxformData *lua = options;
    DetectLuaThreadData *tlua =
            (DetectLuaThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, lua->thread_ctx_id);
    if (tlua == NULL) {
        return;
    }

    lua_getglobal(tlua->luastate, "transform");

    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;

    /* Lua script args are: buffer, rule args table */
    LuaPushStringBuffer(tlua->luastate, input, (size_t)input_len);
    /*
     * Add provided arguments for lua script (these are optionally
     * provided by the rule writer).
     *
     * Start at offset 1 (arg[0] is the lua script filename)
     */
    lua_newtable(tlua->luastate);
    for (int i = 1; i < lua->arg_count + 1; i++) {
        LuaPushInteger(tlua->luastate, i);
        lua_pushstring(tlua->luastate, lua->args[i]);
        lua_settable(tlua->luastate, -3);
    }

    SCLuaSbResetInstructionCounter(tlua->luastate);

    if (LUA_OK != lua_pcall(tlua->luastate, 2, 2, 0)) {
        SCLogDebug("error calling lua script: %s", lua_tostring(tlua->luastate, -1));
    } else {
        /* Lua transform functions must return 2 values: buffer and length */
        int return_value_count = lua_gettop(tlua->luastate);
        if (return_value_count != 2) {
            SCLogDebug("Error: expected 2 return values but got %d", return_value_count);
            goto error;
        }

        if (lua_isstring(tlua->luastate, -2)) {
            const char *transformed_buffer = lua_tostring(tlua->luastate, -2);
            lua_Integer transformed_buffer_byte_count = lua_tointeger(tlua->luastate, -1);
            if (transformed_buffer != NULL && transformed_buffer_byte_count > 0)
                InspectionBufferCopy(buffer, (uint8_t *)transformed_buffer,
                        (uint32_t)transformed_buffer_byte_count);
            SCLogDebug("transform returns [nbytes %d] \"%p\"",
                    (uint32_t)transformed_buffer_byte_count, transformed_buffer);
        }
    }

error:
    while (lua_gettop(tlua->luastate) > 0) {
        lua_pop(tlua->luastate, 1);
    }
}

void DetectTransformLuaxformRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].name = "luaxform";
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].desc =
            "pass inspection buffer to a Lua function along with "
            "arguments supplied to the transform";
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].url = "/rules/transforms.html#luaxform";
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].Transform = TransformLuaxform;
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].Free = DetectTransformLuaxformFree;
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].Setup = DetectTransformLuaxformSetup;
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].flags |= SIGMATCH_QUOTES_OPTIONAL;
    sigmatch_table[DETECT_TRANSFORM_LUAXFORM].TransformId = DetectTransformLuaxformId;
}
