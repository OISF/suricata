/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#include "stream-tcp.h"

#include "detect-lua.h"
#include "detect-lua-extensions.h"

#include "util-var-name.h"

#include "util-lua.h"
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
static int g_smtp_generic_list_id = 0;

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
    g_smtp_generic_list_id = DetectBufferTypeRegister("smtp_generic");

    DetectAppLayerInspectEngineRegister("smtp_generic", ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("smtp_generic", ALPROTO_SMTP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    SCLogDebug("registering lua rule option");
}

/* Flags for DetectLuaThreadData. */
#define FLAG_DATATYPE_PACKET                    BIT_U32(0)
#define FLAG_DATATYPE_PAYLOAD                   BIT_U32(1)
#define FLAG_DATATYPE_STREAM                    BIT_U32(2)
#define FLAG_DATATYPE_HTTP_URI                  BIT_U32(3)
#define FLAG_DATATYPE_HTTP_URI_RAW              BIT_U32(4)
#define FLAG_DATATYPE_HTTP_REQUEST_HEADERS      BIT_U32(5)
#define FLAG_DATATYPE_HTTP_REQUEST_HEADERS_RAW  BIT_U32(6)
#define FLAG_DATATYPE_HTTP_REQUEST_COOKIE       BIT_U32(7)
#define FLAG_DATATYPE_HTTP_REQUEST_UA           BIT_U32(8)
#define FLAG_DATATYPE_HTTP_REQUEST_LINE         BIT_U32(9)
#define FLAG_DATATYPE_HTTP_REQUEST_BODY         BIT_U32(10)
#define FLAG_DATATYPE_HTTP_RESPONSE_COOKIE      BIT_U32(11)
#define FLAG_DATATYPE_HTTP_RESPONSE_BODY        BIT_U32(12)
#define FLAG_DATATYPE_HTTP_RESPONSE_HEADERS     BIT_U32(13)
#define FLAG_DATATYPE_HTTP_RESPONSE_HEADERS_RAW BIT_U32(14)
#define FLAG_DATATYPE_DNS_RRNAME                BIT_U32(15)
#define FLAG_DATATYPE_DNS_REQUEST               BIT_U32(16)
#define FLAG_DATATYPE_DNS_RESPONSE              BIT_U32(17)
#define FLAG_DATATYPE_TLS                       BIT_U32(18)
#define FLAG_DATATYPE_SSH                       BIT_U32(19)
#define FLAG_DATATYPE_SMTP                      BIT_U32(20)
#define FLAG_DATATYPE_DNP3                      BIT_U32(21)
#define FLAG_DATATYPE_BUFFER                    BIT_U32(22)
#define FLAG_ERROR_LOGGED                       BIT_U32(23)
#define FLAG_BLOCKED_FUNCTION_LOGGED            BIT_U32(24)
#define FLAG_INSTRUCTION_LIMIT_LOGGED           BIT_U32(25)
#define FLAG_MEMORY_LIMIT_LOGGED                BIT_U32(26)

#define DEFAULT_LUA_ALLOC_LIMIT       500000
#define DEFAULT_LUA_INSTRUCTION_LIMIT 500000

#if 0
/** \brief dump stack from lua state to screen */
void LuaDumpStack(lua_State *state)
{
    int size = lua_gettop(state);
    int i;

    for (i = 1; i <= size; i++) {
        int type = lua_type(state, i);
        printf("Stack size=%d, level=%d, type=%d, ", size, i, type);

        switch (type) {
            case LUA_TFUNCTION:
                printf("function %s", lua_tostring(state, i) ? "true" : "false");
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
#endif

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
            double script_ret = lua_tonumber(tlua->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tlua->luastate, 1);

            if (script_ret == 1.0)
                match = 1;

        /* script returns a table */
        } else if (lua_type(tlua->luastate, 1) == LUA_TTABLE) {
            lua_pushnil(tlua->luastate);
            const char *k, *v;
            while (lua_next(tlua->luastate, -2)) {
                v = lua_tostring(tlua->luastate, -1);
                lua_pop(tlua->luastate, 1);
                k = lua_tostring(tlua->luastate, -1);

                if (!k || !v)
                    continue;

                SCLogDebug("k='%s', v='%s'", k, v);

                if (strcmp(k, "retval") == 0) {
                    int val;
                    if (StringParseInt32(&val, 10, 0, (const char *)v) < 0) {
                        SCLogError("Invalid value "
                                   "for \"retval\" from LUA return table: '%s'",
                                v);
                        match = 0;
                    }
                    else if (val == 1) {
                        match = 1;
                    }
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tlua->luastate, 1);
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
    if (tlua->alproto != ALPROTO_UNKNOWN) {
        if (p->flow == NULL)
            SCReturnInt(0);

        AppProto alproto = p->flow->alproto;
        if (tlua->alproto != alproto)
            SCReturnInt(0);
    }

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    if ((tlua->flags & FLAG_DATATYPE_PAYLOAD) && p->payload_len) {
        lua_pushliteral(tlua->luastate, "payload"); /* stack at -2 */
        LuaPushStringBuffer (tlua->luastate, (const uint8_t *)p->payload, (size_t)p->payload_len); /* stack at -3 */
        lua_settable(tlua->luastate, -3);
    }
    if ((tlua->flags & FLAG_DATATYPE_PACKET) && GET_PKT_LEN(p)) {
        lua_pushliteral(tlua->luastate, "packet"); /* stack at -2 */
        LuaPushStringBuffer (tlua->luastate, (const uint8_t *)GET_PKT_DATA(p), (size_t)GET_PKT_LEN(p)); /* stack at -3 */
        lua_settable(tlua->luastate, -3);
    }
    if (tlua->alproto == ALPROTO_HTTP1) {
        HtpState *htp_state = p->flow->alstate;
        if (htp_state != NULL && htp_state->connp != NULL) {
            htp_tx_t *tx = NULL;
            uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser,
                                                                 STREAM_TOSERVER);
            uint64_t total_txs= AppLayerParserGetTxCnt(p->flow, htp_state);
            for ( ; idx < total_txs; idx++) {
                tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, idx);
                if (tx == NULL)
                    continue;

                if ((tlua->flags & FLAG_DATATYPE_HTTP_REQUEST_LINE) &&
                        htp_tx_request_line(tx) != NULL && bstr_len(htp_tx_request_line(tx)) > 0) {
                    lua_pushliteral(tlua->luastate, "http.request_line"); /* stack at -2 */
                    LuaPushStringBuffer(tlua->luastate,
                            (const uint8_t *)bstr_ptr(htp_tx_request_line(tx)),
                            bstr_len(htp_tx_request_line(tx)));
                    lua_settable(tlua->luastate, -3);
                }
            }
        }
    }

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

    if (tlua->alproto != ALPROTO_UNKNOWN) {
        int alproto = f->alproto;
        if (tlua->alproto != alproto)
            SCReturnInt(0);
    }

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    if (tlua->alproto == ALPROTO_HTTP1) {
        HtpState *htp_state = state;
        if (htp_state != NULL && htp_state->connp != NULL) {
            htp_tx_t *tx = NULL;
            tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, det_ctx->tx_id);
            if (tx != NULL) {
                if ((tlua->flags & FLAG_DATATYPE_HTTP_REQUEST_LINE) &&
                        htp_tx_request_line(tx) != NULL && bstr_len(htp_tx_request_line(tx)) > 0) {
                    lua_pushliteral(tlua->luastate, "http.request_line"); /* stack at -2 */
                    LuaPushStringBuffer(tlua->luastate,
                            (const uint8_t *)bstr_ptr(htp_tx_request_line(tx)),
                            bstr_len(htp_tx_request_line(tx)));
                    lua_settable(tlua->luastate, -3);
                }
            }
        }
    }

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

    t->alproto = lua->alproto;
    t->flags = lua->flags;

    t->luastate = SCLuaSbStateNew(lua->alloc_limit, lua->instruction_limit);
    if (t->luastate == NULL) {
        SCLogError("luastate pool depleted");
        goto error;
    }

    if (lua->allow_restricted_functions) {
        luaL_openlibs(t->luastate);
    } else {
        SCLuaSbLoadLibs(t->luastate);
    }

    LuaRegisterExtensions(t->luastate);

    lua_pushinteger(t->luastate, (lua_Integer)(lua->sid));
    lua_setglobal(t->luastate, "SCRuleSid");
    lua_pushinteger(t->luastate, (lua_Integer)(lua->rev));
    lua_setglobal(t->luastate, "SCRuleRev");
    lua_pushinteger(t->luastate, (lua_Integer)(lua->gid));
    lua_setglobal(t->luastate, "SCRuleGid");

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
    if (lua != NULL)
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
    } else {
        SCLuaSbLoadLibs(luastate);
    }

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

    lua_newtable(luastate); /* stack at -1 */
    if (lua_gettop(luastate) == 0 || lua_type(luastate, 2) != LUA_TTABLE) {
        SCLogError("no table setup");
        goto error;
    }

    lua_pushliteral(luastate, "script_api_ver"); /* stack at -2 */
    lua_pushnumber (luastate, 1); /* stack at -3 */
    lua_settable(luastate, -3);

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
    const char *k, *v;
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
                    ld->flowint[ld->flowints++] = idx;
                    SCLogDebug("script uses flowint %u with script id %u", idx, ld->flowints - 1);
                }
            }
            lua_pop(luastate, 1);
            continue;
        } else if (strcmp(k, "bytevar") == 0) {
            if (lua_istable(luastate, -1)) {
                lua_pushnil(luastate);
                while (lua_next(luastate, -2) != 0) {
                    /* value at -1, key is at -2 which we ignore */
                    const char *value = lua_tostring(luastate, -1);
                    SCLogDebug("value %s", value);
                    /* removes 'value'; keeps 'key' for next iteration */
                    lua_pop(luastate, 1);

                    if (ld->bytevars == DETECT_LUA_MAX_BYTEVARS) {
                        SCLogError("too many bytevars registered");
                        goto error;
                    }

                    DetectByteIndexType idx;
                    if (!DetectByteRetrieveSMVar(value, s, &idx)) {
                        SCLogError("Unknown byte_extract or byte_math var "
                                   "requested by lua script - %s",
                                value);
                        goto error;
                    }
                    ld->bytevar[ld->bytevars++] = idx;
                    SCLogDebug("script uses bytevar %u with script id %u", idx, ld->bytevars - 1);
                }
            }
            lua_pop(luastate, 1);
            continue;
        }

        v = lua_tostring(luastate, -1);
        lua_pop(luastate, 1);
        if (v == NULL)
            continue;

        SCLogDebug("k='%s', v='%s'", k, v);
        if (strcmp(k, "packet") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= FLAG_DATATYPE_PACKET;
        } else if (strcmp(k, "payload") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= FLAG_DATATYPE_PAYLOAD;
        } else if (strcmp(k, "buffer") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= FLAG_DATATYPE_BUFFER;

            ld->buffername = SCStrdup("buffer");
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }
        } else if (strcmp(k, "stream") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= FLAG_DATATYPE_STREAM;

            ld->buffername = SCStrdup("stream");
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }

        } else if (strncmp(k, "http", 4) == 0 && strcmp(v, "true") == 0) {
            if (ld->alproto != ALPROTO_UNKNOWN && ld->alproto != ALPROTO_HTTP1) {
                SCLogError(
                        "can just inspect script against one app layer proto like HTTP at a time");
                goto error;
            }
            if (ld->flags != 0) {
                SCLogError("when inspecting HTTP buffers only a single buffer can be inspected");
                goto error;
            }

            /* http types */
            ld->alproto = ALPROTO_HTTP1;

            if (strcmp(k, "http.uri") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_URI;

            else if (strcmp(k, "http.uri.raw") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_URI_RAW;

            else if (strcmp(k, "http.request_line") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_LINE;

            else if (strcmp(k, "http.request_headers") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_HEADERS;

            else if (strcmp(k, "http.request_headers.raw") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_HEADERS_RAW;

            else if (strcmp(k, "http.request_cookie") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_COOKIE;

            else if (strcmp(k, "http.request_user_agent") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_UA;

            else if (strcmp(k, "http.request_body") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_REQUEST_BODY;

            else if (strcmp(k, "http.response_body") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_RESPONSE_BODY;

            else if (strcmp(k, "http.response_cookie") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_RESPONSE_COOKIE;

            else if (strcmp(k, "http.response_headers") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_RESPONSE_HEADERS;

            else if (strcmp(k, "http.response_headers.raw") == 0)
                ld->flags |= FLAG_DATATYPE_HTTP_RESPONSE_HEADERS_RAW;

            else {
                SCLogError("unsupported http data type %s", k);
                goto error;
            }

            ld->buffername = SCStrdup(k);
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }
        } else if (strncmp(k, "dns", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_DNS;

            if (strcmp(k, "dns.rrname") == 0)
                ld->flags |= FLAG_DATATYPE_DNS_RRNAME;
            else if (strcmp(k, "dns.request") == 0)
                ld->flags |= FLAG_DATATYPE_DNS_REQUEST;
            else if (strcmp(k, "dns.response") == 0)
                ld->flags |= FLAG_DATATYPE_DNS_RESPONSE;

            else {
                SCLogError("unsupported dns data type %s", k);
                goto error;
            }
            ld->buffername = SCStrdup(k);
            if (ld->buffername == NULL) {
                SCLogError("alloc error");
                goto error;
            }
        } else if (strncmp(k, "tls", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_TLS;

            ld->flags |= FLAG_DATATYPE_TLS;

        } else if (strncmp(k, "ssh", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_SSH;

            ld->flags |= FLAG_DATATYPE_SSH;

        } else if (strncmp(k, "smtp", 4) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_SMTP;

            ld->flags |= FLAG_DATATYPE_SMTP;

        } else if (strncmp(k, "dnp3", 4) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_DNP3;

            ld->flags |= FLAG_DATATYPE_DNP3;

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
    DetectLuaData *lua = NULL;

    /* First check if Lua rules are enabled, by default Lua in rules
     * is disabled. */
    int enabled = 0;
    (void)ConfGetBool("security.lua.allow-rules", &enabled);
    if (!enabled) {
        SCLogError("Lua rules disabled by security configuration: security.lua.allow-rules");
        goto error;
    }

    lua = DetectLuaParse(de_ctx, str);
    if (lua == NULL)
        goto error;

    /* Load lua sandbox configurations */
    intmax_t lua_alloc_limit = DEFAULT_LUA_ALLOC_LIMIT;
    intmax_t lua_instruction_limit = DEFAULT_LUA_INSTRUCTION_LIMIT;
    (void)ConfGetInt("security.lua.max-bytes", &lua_alloc_limit);
    (void)ConfGetInt("security.lua.max-instructions", &lua_instruction_limit);
    lua->alloc_limit = lua_alloc_limit;
    lua->instruction_limit = lua_instruction_limit;

    int allow_restricted_functions = 0;
    (void)ConfGetBool("security.lua.allow-restricted-functions", &allow_restricted_functions);
    lua->allow_restricted_functions = allow_restricted_functions;

    if (DetectLuaSetupPrime(de_ctx, lua, s) == -1) {
        goto error;
    }

    lua->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "lua",
            DetectLuaThreadInit, (void *)lua,
            DetectLuaThreadFree, 0);
    if (lua->thread_ctx_id == -1)
        goto error;

    if (lua->alproto != ALPROTO_UNKNOWN) {
        if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, lua->alproto)) {
            goto error;
        }
        s->alproto = lua->alproto;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */

    int list = -1;
    if (lua->alproto == ALPROTO_UNKNOWN) {
        if (lua->flags & FLAG_DATATYPE_STREAM)
            list = DETECT_SM_LIST_PMATCH;
        else {
            if (lua->flags & FLAG_DATATYPE_BUFFER) {
                if (DetectBufferGetActiveList(de_ctx, s) != -1) {
                    list = s->init_data->list;
                } else {
                    SCLogError("Lua and sticky buffer failure");
                    goto error;
                }
            } else
                list = DETECT_SM_LIST_MATCH;
        }

    } else if (lua->alproto == ALPROTO_HTTP1) {
        if (lua->flags & FLAG_DATATYPE_HTTP_RESPONSE_BODY) {
            list = DetectBufferTypeGetByName("file_data");
        } else if (lua->flags & FLAG_DATATYPE_HTTP_REQUEST_BODY) {
            list = DetectBufferTypeGetByName("http_client_body");
        } else if (lua->flags & FLAG_DATATYPE_HTTP_URI) {
            list = DetectBufferTypeGetByName("http_uri");
        } else if (lua->flags & FLAG_DATATYPE_HTTP_URI_RAW) {
            list = DetectBufferTypeGetByName("http_raw_uri");
        } else if (lua->flags & FLAG_DATATYPE_HTTP_REQUEST_COOKIE ||
                   lua->flags & FLAG_DATATYPE_HTTP_RESPONSE_COOKIE) {
            list = DetectBufferTypeGetByName("http_cookie");
        } else if (lua->flags & FLAG_DATATYPE_HTTP_REQUEST_UA) {
            list = DetectBufferTypeGetByName("http_user_agent");
        } else if (lua->flags &
                   (FLAG_DATATYPE_HTTP_REQUEST_HEADERS | FLAG_DATATYPE_HTTP_RESPONSE_HEADERS)) {
            list = DetectBufferTypeGetByName("http_header");
        } else if (lua->flags & (FLAG_DATATYPE_HTTP_REQUEST_HEADERS_RAW |
                                        FLAG_DATATYPE_HTTP_RESPONSE_HEADERS_RAW)) {
            list = DetectBufferTypeGetByName("http_raw_header");
        } else {
            list = DetectBufferTypeGetByName("http_request_line");
        }
    } else if (lua->alproto == ALPROTO_DNS) {
        if (lua->flags & FLAG_DATATYPE_DNS_RRNAME) {
            list = DetectBufferTypeGetByName("dns_query");
        } else if (lua->flags & FLAG_DATATYPE_DNS_REQUEST) {
            list = DetectBufferTypeGetByName("dns_request");
        } else if (lua->flags & FLAG_DATATYPE_DNS_RESPONSE) {
            list = DetectBufferTypeGetByName("dns_response");
        }
    } else if (lua->alproto == ALPROTO_TLS) {
        list = DetectBufferTypeGetByName("tls_generic");
    } else if (lua->alproto == ALPROTO_SSH) {
        list = DetectBufferTypeGetByName("ssh_banner");
    } else if (lua->alproto == ALPROTO_SMTP) {
        list = g_smtp_generic_list_id;
    } else if (lua->alproto == ALPROTO_DNP3) {
        list = DetectBufferTypeGetByName("dnp3");
    } else {
        SCLogError("lua can't be used with protocol %s", AppLayerGetProtoName(lua->alproto));
        goto error;
    }

    if (list == -1) {
        SCLogError("lua can't be used with protocol %s", AppLayerGetProtoName(lua->alproto));
        goto error;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_LUA, (SigMatchCtx *)lua, list) == NULL) {
        goto error;
    }

    return 0;

error:
    if (lua != NULL)
        DetectLuaFree(de_ctx, lua);
    return -1;
}

/** \brief post-sig parse function to set the sid,rev,gid into the
 *         ctx, as this isn't available yet during parsing.
 */
void DetectLuaPostSetup(Signature *s)
{
    int i;
    SigMatch *sm;

    for (i = 0; i < DETECT_SM_LIST_MAX; i++) {
        for (sm = s->init_data->smlists[i]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_LUA)
                continue;

            DetectLuaData *ld = (DetectLuaData *)sm->ctx;
            ld->sid = s->id;
            ld->rev = s->rev;
            ld->gid = s->gid;
        }
    }
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

        DetectUnregisterThreadCtxFuncs(de_ctx, lua, "lua");

        SCFree(lua);
    }
}

#ifdef UNITTESTS
#include "detect-engine-alert.h"

/** \test http buffer */
static int LuaMatchTest01(void)
{
    ConfSetFinal("security.lua.allow-rules", "true");

    const char script[] =
        "function init (args)\n"
        "   local needs = {}\n"
        "   needs[\"http.request_headers\"] = tostring(true)\n"
        "   needs[\"flowvar\"] = {\"cnt\"}\n"
        "   return needs\n"
        "end\n"
        "\n"
        "function match(args)\n"
        "   a = ScFlowvarGet(0)\n"
        "   if a then\n"
        "       a = tostring(tonumber(a)+1)\n"
        "       print (a)\n"
        "       ScFlowvarSet(0, a, #a)\n"
        "   else\n"
        "       a = tostring(1)\n"
        "       print (a)\n"
        "       ScFlowvarSet(0, a, #a)\n"
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
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int LuaMatchTest01a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowvar\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = SCFlowvarGet(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
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
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test payload buffer */
static int LuaMatchTest02(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"payload\"] = tostring(true)\n"
                          "   needs[\"flowvar\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = ScFlowvarGet(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       ScFlowvarSet(0, a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       ScFlowvarSet(0, a, #a)\n"
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

    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test payload buffer */
static int LuaMatchTest02a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"payload\"] = tostring(true)\n"
                          "   needs[\"flowvar\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = SCFlowvarGet(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
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

    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test packet buffer */
static int LuaMatchTest03(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"packet\"] = tostring(true)\n"
                          "   needs[\"flowvar\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = ScFlowvarGet(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       ScFlowvarSet(0, a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       ScFlowvarSet(0, a, #a)\n"
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

    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test packet buffer */
static int LuaMatchTest03a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"packet\"] = tostring(true)\n"
                          "   needs[\"flowvar\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   a = SCFlowvarGet(0)\n"
                          "   if a then\n"
                          "       a = tostring(tonumber(a)+1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
                          "   else\n"
                          "       a = tostring(1)\n"
                          "       print (a)\n"
                          "       SCFlowvarSet(0, a, #a)\n"
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

    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest04(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = ScFlowintGet(0)\n"
                          "   if a then\n"
                          "       ScFlowintSet(0, a + 1)\n"
                          "   else\n"
                          "       ScFlowintSet(0, 1)\n"
                          "   end\n"
                          "   \n"
                          "   a = ScFlowintGet(0)\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest04a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = SCFlowintGet(0)\n"
                          "   if a then\n"
                          "       SCFlowintSet(0, a + 1)\n"
                          "   else\n"
                          "       SCFlowintSet(0, 1)\n"
                          "   end\n"
                          "   \n"
                          "   a = SCFlowintGet(0)\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest05(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = ScFlowintIncr(0)\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest05a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = SCFlowintIncr(0)\n"
                          "   if a == 2 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest06(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = ScFlowintGet(0)\n"
                          "   if a == nil then\n"
                          "       print \"new var set to 2\""
                          "       ScFlowintSet(0, 2)\n"
                          "   end\n"
                          "   a = ScFlowintDecr(0)\n"
                          "   if a == 0 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    FAIL_IF(fv->data.fv_int.value != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/** \test http buffer, flowints */
static int LuaMatchTest06a(void)
{
    const char script[] = "function init (args)\n"
                          "   local needs = {}\n"
                          "   needs[\"http.request_headers\"] = tostring(true)\n"
                          "   needs[\"flowint\"] = {\"cnt\"}\n"
                          "   return needs\n"
                          "end\n"
                          "\n"
                          "function match(args)\n"
                          "   print \"inspecting\""
                          "   a = SCFlowintGet(0)\n"
                          "   if a == nil then\n"
                          "       print \"new var set to 2\""
                          "       SCFlowintSet(0, 2)\n"
                          "   end\n"
                          "   a = SCFlowintDecr(0)\n"
                          "   if a == 0 then\n"
                          "       print \"match\"\n"
                          "       return 1\n"
                          "   end\n"
                          "   return 0\n"
                          "end\n"
                          "return 0\n";
    char sig[] = "alert http any any -> any any (flow:to_server; lua:unittest; sid:1;)";
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

    FAIL_IF(fv->data.fv_int.value != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
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
