/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "conf.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-build.h"

#include "detect-byte.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-byte.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-ssl.h"

#include "stream-tcp.h"

#include "detect-lua.h"
#include "detect-lua-extensions.h"

#include "util-var-name.h"

#include "util-lua.h"
#include "util-lua-builtins.h"
#include "util-lua-common.h"
#include "util-lua-sandbox.h"

static int DetectLuaMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectLuaAppTxMatch (DetectEngineThreadCtx *det_ctx,
                                Flow *f, uint8_t flags,
                                void *state, void *txv, const Signature *s,
                                const SigMatchCtx *ctx);
static int DetectLuaSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectLuaRegisterTests(void);
#endif
static void DetectLuaFree(DetectEngineCtx *, void *);
static int g_lua_ja3_list_id = 0;
static int g_lua_ja3s_list_id = 0;

/**
 * \brief Registration function for keyword: lua
 */
void DetectLuaRegister(void)
{
    sigmatch_table[DETECT_LUA].name = "lua";
    sigmatch_table[DETECT_LUA].desc = "match via a lua script";
    sigmatch_table[DETECT_LUA].url = "/rules/rule-lua-scripting.html";
    sigmatch_table[DETECT_LUA].Match = DetectLuaMatch;
    sigmatch_table[DETECT_LUA].AppLayerTxMatch = DetectLuaAppTxMatch;
    sigmatch_table[DETECT_LUA].Setup = DetectLuaSetup;
    sigmatch_table[DETECT_LUA].Free  = DetectLuaFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_LUA].RegisterTests = DetectLuaRegisterTests;
#endif

    g_lua_ja3_list_id = DetectBufferTypeRegister("ja3.lua");
    DetectAppLayerInspectEngineRegister("ja3.lua", ALPROTO_TLS, SIG_FLAG_TOSERVER,
            TLS_STATE_CLIENT_HELLO_DONE, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "ja3.lua", ALPROTO_QUIC, SIG_FLAG_TOSERVER, 1, DetectEngineInspectGenericList, NULL);

    g_lua_ja3s_list_id = DetectBufferTypeRegister("ja3s.lua");
    DetectAppLayerInspectEngineRegister("ja3s.lua", ALPROTO_TLS, SIG_FLAG_TOCLIENT,
            TLS_STATE_SERVER_HELLO_DONE, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "ja3s.lua", ALPROTO_QUIC, SIG_FLAG_TOCLIENT, 1, DetectEngineInspectGenericList, NULL);

    SCLogDebug("registering lua rule option");
}

/* Flags for DetectLuaThreadData. */
#define FLAG_DATATYPE_PACKET                    BIT_U32(0)
#define FLAG_DATATYPE_PAYLOAD                   BIT_U32(1)
#define FLAG_DATATYPE_STREAM                    BIT_U32(2)
#define FLAG_LIST_JA3                           BIT_U32(3)
#define FLAG_LIST_JA3S                          BIT_U32(4)
#define FLAG_DATATYPE_BUFFER                    BIT_U32(22)
#define FLAG_ERROR_LOGGED                       BIT_U32(23)
#define FLAG_BLOCKED_FUNCTION_LOGGED            BIT_U32(24)
#define FLAG_INSTRUCTION_LIMIT_LOGGED           BIT_U32(25)
#define FLAG_MEMORY_LIMIT_LOGGED                BIT_U32(26)

#define DEFAULT_LUA_ALLOC_LIMIT       500000
#define DEFAULT_LUA_INSTRUCTION_LIMIT 500000

/** \brief dump stack from lua state to screen */
void LuaDumpStack(lua_State *state, const char *prefix)
{
    int size = lua_gettop(state);
    printf("%s: size %d\n", prefix, size);

    for (int i = 1; i <= size; i++) {
        int type = lua_type(state, i);
        printf("- %s: Stack size=%d, level=%d, type=%d, ", prefix, size, i, type);

        switch (type) {
            case LUA_TFUNCTION:
                printf("function %s", lua_tostring(state, i));
                break;
            case LUA_TBOOLEAN:
                printf("bool %s", lua_toboolean(state, i) ? "true" : "false");
                break;
            case LUA_TNUMBER:
                printf("number %g", lua_tonumber(state, i));
                break;
            case LUA_TSTRING:
                printf("string `%s'", lua_tostring(state, i));
                break;
            case LUA_TTABLE:
                printf("table `%s'", lua_tostring(state, i));
                break;
            default:
                printf("other %s", lua_typename(state, type));
                break;

        }
        printf("\n");
    }
}

static void LuaStateSetDetectLuaData(lua_State *state, DetectLuaData *data)
{
    lua_pushlightuserdata(state, (void *)&luaext_key_ld);
    lua_pushlightuserdata(state, (void *)data);
    lua_settable(state, LUA_REGISTRYINDEX);
}

/**
 * \brief Common function to run the Lua match function and process
 *     the return value.
 */
static int DetectLuaRunMatch(
        DetectEngineThreadCtx *det_ctx, const DetectLuaData *lua, DetectLuaThreadData *tlua)
{
    /* Reset instruction count. */
    SCLuaSbResetInstructionCounter(tlua->luastate);

    if (lua_pcall(tlua->luastate, 1, 1, 0) != 0) {
        const char *reason = lua_tostring(tlua->luastate, -1);
        SCLuaSbState *context = SCLuaSbGetContext(tlua->luastate);
        uint32_t flag = 0;
        if (context->blocked_function_error) {
            StatsIncr(det_ctx->tv, det_ctx->lua_blocked_function_errors);
            flag = FLAG_BLOCKED_FUNCTION_LOGGED;
        } else if (context->instruction_count_error) {
            StatsIncr(det_ctx->tv, det_ctx->lua_instruction_limit_errors);
            flag = FLAG_INSTRUCTION_LIMIT_LOGGED;
        } else if (context->memory_limit_error) {
            StatsIncr(det_ctx->tv, det_ctx->lua_memory_limit_errors);
            reason = "memory limit exceeded";
            flag = FLAG_MEMORY_LIMIT_LOGGED;
        } else {
            flag = FLAG_ERROR_LOGGED;
        }

        /* Log once per thread per error type, the message from Lua
         * will include the filename. */
        if (!(tlua->flags & flag)) {
            SCLogWarning("Lua script failed to run successfully: %s", reason);
            tlua->flags |= flag;
        }

        StatsIncr(det_ctx->tv, det_ctx->lua_rule_errors);
        while (lua_gettop(tlua->luastate) > 0) {
            lua_pop(tlua->luastate, 1);
        }
        SCReturnInt(0);
    }

    int match = 0;

    /* process returns from script */
    if (lua_gettop(tlua->luastate) > 0) {
        /* script returns a number (return 1 or return 0) */
        if (lua_type(tlua->luastate, 1) == LUA_TNUMBER) {
            lua_Integer script_ret = lua_tointeger(tlua->luastate, 1);
            SCLogDebug("script_ret %lld", script_ret);
            lua_pop(tlua->luastate, 1);
            if (script_ret == 1)
                match = 1;
        } else {
            SCLogDebug("Unsupported datatype returned from Lua script");
        }
    }

    if (lua->negated) {
        if (match == 1)
            match = 0;
        else
            match = 1;
    }

    while (lua_gettop(tlua->luastate) > 0) {
        lua_pop(tlua->luastate, 1);
    }

    SCReturnInt(match);
}

int DetectLuaMatchBuffer(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchData *smd, const uint8_t *buffer, uint32_t buffer_len, uint32_t offset,
        Flow *f)
{
    SCEnter();

    if (buffer == NULL || buffer_len == 0)
        SCReturnInt(0);

    DetectLuaData *lua = (DetectLuaData *)smd->ctx;
    if (lua == NULL)
        SCReturnInt(0);

    DetectLuaThreadData *tlua =
            (DetectLuaThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, lua->thread_ctx_id);
    if (tlua == NULL)
        SCReturnInt(0);

    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, f, /* no packet in the ctx */ NULL, s, 0);

    /* prepare data to pass to script */
    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    lua_pushliteral(tlua->luastate, "offset"); /* stack at -2 */
    lua_pushnumber(tlua->luastate, (int)(offset + 1));
    lua_settable(tlua->luastate, -3);

    lua_pushstring(tlua->luastate, lua->buffername); /* stack at -2 */
    LuaPushStringBuffer(tlua->luastate, (const uint8_t *)buffer, (size_t)buffer_len);
    lua_settable(tlua->luastate, -3);

    SCReturnInt(DetectLuaRunMatch(det_ctx, lua, tlua));
}

/**
 * \brief match the specified lua script
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param p packet
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectLuaData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectLuaMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    DetectLuaData *lua = (DetectLuaData *)ctx;
    if (lua == NULL)
        SCReturnInt(0);

    DetectLuaThreadData *tlua = (DetectLuaThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, lua->thread_ctx_id);
    if (tlua == NULL)
        SCReturnInt(0);

    /* setup extension data for use in lua c functions */
    uint8_t flags = 0;
    if (p->flowflags & FLOW_PKT_TOSERVER)
        flags = STREAM_TOSERVER;
    else if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags = STREAM_TOCLIENT;

    LuaStateSetThreadVars(tlua->luastate, det_ctx->tv);

    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, p->flow, p, s, flags);

    if ((tlua->flags & FLAG_DATATYPE_PAYLOAD) && p->payload_len == 0)
        SCReturnInt(0);
    if ((tlua->flags & FLAG_DATATYPE_PACKET) && GET_PKT_LEN(p) == 0)
        SCReturnInt(0);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    SCReturnInt(DetectLuaRunMatch(det_ctx, lua, tlua));
}

static int DetectLuaAppMatchCommon (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state,
        const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    DetectLuaData *lua = (DetectLuaData *)ctx;
    if (lua == NULL)
        SCReturnInt(0);

    DetectLuaThreadData *tlua = (DetectLuaThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, lua->thread_ctx_id);
    if (tlua == NULL)
        SCReturnInt(0);

    /* setup extension data for use in lua c functions */
    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, f, NULL, s, flags);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    SCReturnInt(DetectLuaRunMatch(det_ctx, lua, tlua));
}

/**
 * \brief match the specified lua script in a list with a tx
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectLuaData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectLuaAppTxMatch (DetectEngineThreadCtx *det_ctx,
                                Flow *f, uint8_t flags,
                                void *state, void *txv, const Signature *s,
                                const SigMatchCtx *ctx)
{
    return DetectLuaAppMatchCommon(det_ctx, f, flags, state, s, ctx);
}

#ifdef UNITTESTS
/* if this ptr is set the lua setup functions will use this buffer as the
 * lua script instead of calling luaL_loadfile on the filename supplied. */
static const char *ut_script = NULL;
#endif

static void *DetectLuaThreadInit(void *data)
{
    int status;
    DetectLuaData *lua = (DetectLuaData *)data;
    BUG_ON(lua == NULL);

    DetectLuaThreadData *t = SCCalloc(1, sizeof(DetectLuaThreadData));
    if (unlikely(t == NULL)) {
        SCLogError("couldn't alloc ctx memory");
        return NULL;
    }

    t->flags = lua->flags;

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

    LuaStateSetDetectLuaData(t->luastate, lua);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#ifdef UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(t->luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError("couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(t->luastate, lua->filename);
        if (status) {
            SCLogError("couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
        SCLogError("couldn't prime file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

    /* thread_init call */
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

static void DetectLuaThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectLuaThreadData *t = (DetectLuaThreadData *)ctx;
        if (t->luastate != NULL)
            SCLuaSbStateClose(t->luastate);
        SCFree(t);
    }
}

/**
 * \brief Parse the lua keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param str Pointer to the user provided option
 *
 * \retval lua pointer to DetectLuaData on success
 * \retval NULL on failure
 */
static DetectLuaData *DetectLuaParse (DetectEngineCtx *de_ctx, const char *str)
{
    DetectLuaData *lua = NULL;

    /* We have a correct lua option */
    lua = SCCalloc(1, sizeof(DetectLuaData));
    if (unlikely(lua == NULL))
        goto error;

    if (strlen(str) && str[0] == '!') {
        lua->negated = 1;
        str++;
    }

    /* get full filename */
    lua->filename = DetectLoadCompleteSigPath(de_ctx, str);
    if (lua->filename == NULL) {
        goto error;
    }

    return lua;

error:
    DetectLuaFree(de_ctx, lua);
    return NULL;
}

static int DetectLuaSetupPrime(DetectEngineCtx *de_ctx, DetectLuaData *ld, const Signature *s)
{
    int status;

    lua_State *luastate = SCLuaSbStateNew(ld->alloc_limit, ld->instruction_limit);
    if (luastate == NULL)
        return -1;
    if (ld->allow_restricted_functions) {
        luaL_openlibs(luastate);
        SCLuaRequirefBuiltIns(luastate);
    } else {
        SCLuaSbLoadLibs(luastate);
    }
    LuaStateSetDetectLuaData(luastate, ld);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#ifdef UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError("couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, ld->filename);
        if (status) {
            SCLogError("couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError("couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "init");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError("no init function in script");
        goto error;
    }

    /* Pass the signature as the first argument, setting up bytevars depends on
     * access to the signature. */
    lua_pushlightuserdata(luastate, (void *)s);

    if (lua_pcall(luastate, 1, 1, 0) != 0) {
        SCLogError("couldn't run script 'init' function: %s", lua_tostring(luastate, -1));
        goto error;
    }

    /* process returns from script */
    if (lua_gettop(luastate) == 0) {
        SCLogError("init function in script should return table, nothing returned");
        goto error;
    }
    if (lua_type(luastate, 1) != LUA_TTABLE) {
        SCLogError("init function in script should return table, returned is not table");
        goto error;
    }

    lua_pushnil(luastate);
    const char *k;
    while (lua_next(luastate, -2)) {
        k = lua_tostring(luastate, -2);
        if (k == NULL)
            continue;

        /* handle flowvar and bytes separately as they have a table as value */
        if (strcmp(k, "flowvar") == 0) {
            if (lua_istable(luastate, -1)) {
                lua_pushnil(luastate);
                while (lua_next(luastate, -2) != 0) {
                    /* value at -1, key is at -2 which we ignore */
                    const char *value = lua_tostring(luastate, -1);
                    SCLogDebug("value %s", value);
                    /* removes 'value'; keeps 'key' for next iteration */
                    lua_pop(luastate, 1);

                    if (ld->flowvars == DETECT_LUA_MAX_FLOWVARS) {
                        SCLogError("too many flowvars registered");
                        goto error;
                    }

                    uint32_t idx = VarNameStoreRegister(value, VAR_TYPE_FLOW_VAR);
                    if (unlikely(idx == 0))
                        goto error;
                    ld->flowvar[ld->flowvars++] = idx;
                    SCLogDebug("script uses flowvar %u with script id %u", idx, ld->flowvars - 1);
                }
            }
            lua_pop(luastate, 1);
            continue;
        } else if (strcmp(k, "flowint") == 0) {
            if (lua_istable(luastate, -1)) {
                lua_pushnil(luastate);
                while (lua_next(luastate, -2) != 0) {
                    /* value at -1, key is at -2 which we ignore */
                    const char *value = lua_tostring(luastate, -1);
                    SCLogDebug("value %s", value);
                    /* removes 'value'; keeps 'key' for next iteration */
                    lua_pop(luastate, 1);

                    if (ld->flowints == DETECT_LUA_MAX_FLOWINTS) {
                        SCLogError("too many flowints registered");
                        goto error;
                    }

                    uint32_t idx = VarNameStoreRegister(value, VAR_TYPE_FLOW_INT);
                    if (unlikely(idx == 0))
                        goto error;
                    ld->flowint[ld->flowints++] = idx;
                    SCLogDebug("script uses flowint %u with script id %u", idx, ld->flowints - 1);
                }
            }
            lua_pop(luastate, 1);
            continue;
        }

        bool required = lua_toboolean(luastate, -1);
        lua_pop(luastate, 1);
        if (!required) {
            continue;
        }

        if (strcmp(k, "ja3") == 0) {
            ld->flags |= FLAG_LIST_JA3;
        } else if (strcmp(k, "ja3s") == 0) {
            ld->flags |= FLAG_LIST_JA3S;
        } else if (strcmp(k, "packet") == 0) {
            ld->flags |= FLAG_DATATYPE_PACKET;
        } else if (strcmp(k, "payload") == 0) {
            ld->flags |= FLAG_DATATYPE_PAYLOAD;
        } else if (strcmp(k, "buffer") == 0) {
            ld->flags |= FLAG_DATATYPE_BUFFER;

            ld->buffername = SCStrdup("buffer");
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }
        } else if (strcmp(k, "stream") == 0) {
            ld->flags |= FLAG_DATATYPE_STREAM;

            ld->buffername = SCStrdup("stream");
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }
            /* old options no longer supported */
        } else if (strncmp(k, "http", 4) == 0 || strncmp(k, "dns", 3) == 0 ||
                   strncmp(k, "tls", 3) == 0 || strncmp(k, "ssh", 3) == 0 ||
                   strncmp(k, "smtp", 4) == 0 || strncmp(k, "dnp3", 4) == 0) {
            SCLogError("data type %s no longer supported, use rule hooks", k);
            goto error;

        } else {
            SCLogError("unsupported data type %s", k);
            goto error;
        }
    }

    /* pop the table */
    lua_pop(luastate, 1);
    SCLuaSbStateClose(luastate);
    return 0;
error:
    SCLuaSbStateClose(luastate);
    return -1;
}

/**
 * \brief this function is used to parse lua options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "lua" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectLuaSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    /* First check if Lua rules are enabled, by default Lua in rules
     * is disabled. */
    int enabled = 0;
    if (SCConfGetBool("security.lua.allow-rules", &enabled) == 1 && !enabled) {
        SCLogError("Lua rules disabled by security configuration: security.lua.allow-rules");
        return -1;
    }

    DetectLuaData *lua = DetectLuaParse(de_ctx, str);
    if (lua == NULL)
        return -1;

    /* Load lua sandbox configurations */
    intmax_t lua_alloc_limit = DEFAULT_LUA_ALLOC_LIMIT;
    intmax_t lua_instruction_limit = DEFAULT_LUA_INSTRUCTION_LIMIT;
    (void)SCConfGetInt("security.lua.max-bytes", &lua_alloc_limit);
    (void)SCConfGetInt("security.lua.max-instructions", &lua_instruction_limit);
    lua->alloc_limit = lua_alloc_limit;
    lua->instruction_limit = lua_instruction_limit;

    int allow_restricted_functions = 0;
    (void)SCConfGetBool("security.lua.allow-restricted-functions", &allow_restricted_functions);
    lua->allow_restricted_functions = allow_restricted_functions;

    if (DetectLuaSetupPrime(de_ctx, lua, s) == -1) {
        goto error;
    }

    lua->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "lua",
            DetectLuaThreadInit, (void *)lua,
            DetectLuaThreadFree, 0);
    if (lua->thread_ctx_id == -1)
        goto error;

    int list = DetectBufferGetActiveList(de_ctx, s);
    SCLogDebug("buffer list %d -> %d", list, s->init_data->list);
    if (list == -1 || (list == 0 && s->init_data->list == INT_MAX)) {
        /* what needs to happen here is: we register to the rule hook, so e.g.
         * http1.request_complete. This means we need a list.
         *
         * This includes each pkt, payload, stream, etc. */

        if (s->init_data->hook.type != SIGNATURE_HOOK_TYPE_NOT_SET) {
            list = s->init_data->hook.sm_list;
            SCLogDebug("setting list %d", list);
        }
    }

    if (list == -1) {
        SCLogError("lua failed to set up");
        goto error;
    }
    if (list == 0) {
        if (lua->flags & FLAG_LIST_JA3) {
            list = g_lua_ja3_list_id;
        } else if (lua->flags & FLAG_LIST_JA3S) {
            list = g_lua_ja3s_list_id;
        }
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_LUA, (SigMatchCtx *)lua, list) == NULL) {
        goto error;
    }

    return 0;

error:
    if (lua != NULL)
        DetectLuaFree(de_ctx, lua);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectLuaData
 *
 * \param ptr pointer to DetectLuaData
 */
static void DetectLuaFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectLuaData *lua = (DetectLuaData *)ptr;

        if (lua->buffername)
            SCFree(lua->buffername);
        if (lua->filename)
            SCFree(lua->filename);

        for (uint16_t i = 0; i < lua->flowints; i++) {
            VarNameStoreUnregister(lua->flowint[i], VAR_TYPE_FLOW_INT);
        }
        for (uint16_t i = 0; i < lua->flowvars; i++) {
            VarNameStoreUnregister(lua->flowvar[i], VAR_TYPE_FLOW_VAR);
        }
        for (uint16_t i = 0; i < lua->bytevars; i++) {
            SCFree(lua->bytevar[i].name);
        }

        DetectUnregisterThreadCtxFuncs(de_ctx, lua, "lua");

        SCFree(lua);
    }
}

#ifdef UNITTESTS
#include "detect-engine-alert.h"

/** \test http buffer */
static int LuaMatchTest01(void)
{
    SCConfSetFinal("security.lua.allow-rules", "true");

    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SCLogDebug("inspecting p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SCLogDebug("inspecting p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);

    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int LuaMatchTest01a(void)
{
    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SCLogDebug("inspecting p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    /* do detect for p2 */
    SCLogDebug("inspecting p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);

    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test payload buffer */
static int LuaMatchTest02(void)
{
    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")\n"
                          "   local needs = {}\n"
                          "   needs[\"payload\"] = tostring(true)\n"
                          "   return needs\n"
                          "end\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert tcp any any -> any any (flow:to_server; lua:unittest; sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);

    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test payload buffer */
static int LuaMatchTest02a(void)
{
    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")"
                          "   local needs = {}\n"
                          "   needs[\"payload\"] = tostring(true)\n"
                          "   return needs\n"
                          "end\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert tcp any any -> any any (flow:to_server; lua:unittest; sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);

    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test packet buffer */
static int LuaMatchTest03(void)
{
    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")\n"
                          "   local needs = {}\n"
                          "   needs[\"packet\"] = tostring(true)\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert tcp any any -> any any (flow:to_server; lua:unittest; sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test packet buffer */
static int LuaMatchTest03a(void)
{
    const char script[] = "local flowvarlib = require(\"suricata.flowvar\")\n"
                          "function init (args)\n"
                          "   flowvarlib.register(\"cnt\")\n"
                          "   local needs = {}\n"
                          "   needs[\"packet\"] = tostring(true)\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowvarlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       cnt:set(a, #a)\n"
                          "   end\n"
                          "   \n"
                          "   print (\"pre check: \" .. (a))\n"
                          "   if tonumber(a) == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert tcp any any -> any any (flow:to_server; lua:unittest; sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_VAR);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_str.value_len != 1);
    FAIL_IF(memcmp(fv->data.fv_str.value, "2", 1) != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest04(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       cnt:set(a + 1)\n"
                          "   else\n"
                          "       cnt:set(1)\n"
                          "   end\n"
                          "   \n"
                          "   a = cnt:value()\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 2);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest04a(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:value()\n"
                          "   if a then\n"
                          "       cnt:set(a + 1)\n"
                          "   else\n"
                          "       cnt:set(1)\n"
                          "   end\n"
                          "   \n"
                          "   a = cnt:value()\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 2);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest05(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:incr()\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 2);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest05a(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:incr()\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 2);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest06(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:value()\n"
                          "   if a == nil then\n"
                          "       print \"new var set to 2\""
                          "       cnt:set(2)\n"
                          "   end\n"
                          "   a = cnt:decr()\n"
                          "   if a == 0 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest06a(void)
{
    const char script[] = "local flowintlib = require(\"suricata.flowint\")\n"
                          "function init (args)\n"
                          "   flowintlib.register(\"cnt\")\n"
                          "   return {}\n"
                          "end\n"
                          "\n"
                          "function thread_init (args)\n"
                          "   cnt = flowintlib.get(\"cnt\")\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = cnt:value()\n"
                          "   if a == nil then\n"
                          "       print \"new var set to 2\""
                          "       cnt:set(2)\n"
                          "   end\n"
                          "   a = cnt:decr()\n"
                          "   if a == 0 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http1:request_complete any any -> any any (flow:to_server; lua:unittest; "
                 "sid:1;)";
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    uint32_t id = VarNameStoreLookupByName("cnt", VAR_TYPE_FLOW_INT);
    FAIL_IF(id == 0);
    FlowVar *fv = FlowVarGet(&f, id);
    FAIL_IF_NULL(fv);
    FAIL_IF(fv->data.fv_int.value != 0);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

void DetectLuaRegisterTests(void)
{
    UtRegisterTest("LuaMatchTest01", LuaMatchTest01);
    UtRegisterTest("LuaMatchTest01a", LuaMatchTest01a);
    UtRegisterTest("LuaMatchTest02", LuaMatchTest02);
    UtRegisterTest("LuaMatchTest02a", LuaMatchTest02a);
    UtRegisterTest("LuaMatchTest03", LuaMatchTest03);
    UtRegisterTest("LuaMatchTest03a", LuaMatchTest03a);
    UtRegisterTest("LuaMatchTest04", LuaMatchTest04);
    UtRegisterTest("LuaMatchTest04a", LuaMatchTest04a);
    UtRegisterTest("LuaMatchTest05", LuaMatchTest05);
    UtRegisterTest("LuaMatchTest05a", LuaMatchTest05a);
    UtRegisterTest("LuaMatchTest06", LuaMatchTest06);
    UtRegisterTest("LuaMatchTest06a", LuaMatchTest06a);
}
#endif
