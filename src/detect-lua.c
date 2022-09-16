/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#ifdef UNITTESTS
#include "util-lua.h"
#include "util-var-name.h"
#include "util-cpu.h"
#include "queue.h"
#include "detect-lua-extensions.h"
#include "stream-tcp.h"
#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "app-layer.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-print.h"
#include "util-spm-bm.h"
#include "util-debug.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow.h"
#include "detect-byte.h"
#include "detect-engine-build.h"
#include "detect-engine-state.h"
#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect.h"
#include "decode.h"
#include "debug.h"
#include "threads.h"
#include "conf.h"
#endif

#include "detect-lua.h"

#ifndef HAVE_LUA

static int DetectLuaSetupNoSupport (DetectEngineCtx *a, Signature *b, const char *c)
{
    SCLogError(SC_ERR_NO_LUA_SUPPORT, "no Lua support built in, needed for lua/luajit keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: lua
 */
void DetectLuaRegister(void)
{
    sigmatch_table[DETECT_LUA].name = "lua";
    sigmatch_table[DETECT_LUA].alias = "luajit";
    sigmatch_table[DETECT_LUA].desc = "support for lua scripting";
    sigmatch_table[DETECT_LUA].url = "/rules/rule-lua-scripting.html";
    sigmatch_table[DETECT_LUA].Setup = DetectLuaSetupNoSupport;
    sigmatch_table[DETECT_LUA].Free  = NULL;
    sigmatch_table[DETECT_LUA].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering lua rule option");
    return;
}

#else /* HAVE_LUA */

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
    sigmatch_table[DETECT_LUA].alias = "luajit";
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

    DetectAppLayerInspectEngineRegister2("smtp_generic", ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2("smtp_generic", ALPROTO_SMTP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    SCLogDebug("registering lua rule option");
    return;
}

#define DATATYPE_PACKET  BIT_U32(0)
#define DATATYPE_PAYLOAD BIT_U32(1)
#define DATATYPE_STREAM  BIT_U32(2)

#define DATATYPE_HTTP_URI     BIT_U32(3)
#define DATATYPE_HTTP_URI_RAW BIT_U32(4)

#define DATATYPE_HTTP_REQUEST_HEADERS     BIT_U32(5)
#define DATATYPE_HTTP_REQUEST_HEADERS_RAW BIT_U32(6)
#define DATATYPE_HTTP_REQUEST_COOKIE      BIT_U32(7)
#define DATATYPE_HTTP_REQUEST_UA          BIT_U32(8)

#define DATATYPE_HTTP_REQUEST_LINE BIT_U32(9)
#define DATATYPE_HTTP_REQUEST_BODY BIT_U32(10)

#define DATATYPE_HTTP_RESPONSE_COOKIE BIT_U32(11)
#define DATATYPE_HTTP_RESPONSE_BODY   BIT_U32(12)

#define DATATYPE_HTTP_RESPONSE_HEADERS     BIT_U32(13)
#define DATATYPE_HTTP_RESPONSE_HEADERS_RAW BIT_U32(14)

#define DATATYPE_DNS_RRNAME   BIT_U32(15)
#define DATATYPE_DNS_REQUEST  BIT_U32(16)
#define DATATYPE_DNS_RESPONSE BIT_U32(17)

#define DATATYPE_TLS  BIT_U32(18)
#define DATATYPE_SSH  BIT_U32(19)
#define DATATYPE_SMTP BIT_U32(20)

#define DATATYPE_DNP3 BIT_U32(21)

#define DATATYPE_BUFFER BIT_U32(22)

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

int DetectLuaMatchBuffer(DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        const uint8_t *buffer, uint32_t buffer_len, uint32_t offset,
        Flow *f)
{
    SCEnter();
    int ret = 0;

    if (buffer == NULL || buffer_len == 0)
        SCReturnInt(0);

    DetectLuaData *lua = (DetectLuaData *)smd->ctx;
    if (lua == NULL)
        SCReturnInt(0);

    DetectLuaThreadData *tlua = (DetectLuaThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, lua->thread_ctx_id);
    if (tlua == NULL)
        SCReturnInt(0);

    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, f, /* no packet in the ctx */ NULL, s, 0);

    /* prepare data to pass to script */
    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    lua_pushliteral (tlua->luastate, "offset"); /* stack at -2 */
    lua_pushnumber (tlua->luastate, (int)(offset + 1));
    lua_settable(tlua->luastate, -3);

    lua_pushstring (tlua->luastate, lua->buffername); /* stack at -2 */
    LuaPushStringBuffer(tlua->luastate, (const uint8_t *)buffer, (size_t)buffer_len);
    lua_settable(tlua->luastate, -3);

    int retval = lua_pcall(tlua->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tlua->luastate, -1));
    }

    /* process returns from script */
    if (lua_gettop(tlua->luastate) > 0) {
        /* script returns a number (return 1 or return 0) */
        if (lua_type(tlua->luastate, 1) == LUA_TNUMBER) {
            double script_ret = lua_tonumber(tlua->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tlua->luastate, 1);

            if (script_ret == 1.0)
                ret = 1;

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
                        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value "
                                   "for \"retval\" from LUA return table: '%s'", v);
                        ret = 0;
                    }
                    else if (val == 1) {
                        ret = 1;
                    }
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tlua->luastate, 1);
        }
    } else {
        SCLogDebug("no stack");
    }

    /* clear the stack */
    while (lua_gettop(tlua->luastate) > 0) {
        lua_pop(tlua->luastate, 1);
    }

    if (lua->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
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
    int ret = 0;
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

    if ((tlua->flags & DATATYPE_PAYLOAD) && p->payload_len == 0)
        SCReturnInt(0);
    if ((tlua->flags & DATATYPE_PACKET) && GET_PKT_LEN(p) == 0)
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

    if ((tlua->flags & DATATYPE_PAYLOAD) && p->payload_len) {
        lua_pushliteral(tlua->luastate, "payload"); /* stack at -2 */
        LuaPushStringBuffer (tlua->luastate, (const uint8_t *)p->payload, (size_t)p->payload_len); /* stack at -3 */
        lua_settable(tlua->luastate, -3);
    }
    if ((tlua->flags & DATATYPE_PACKET) && GET_PKT_LEN(p)) {
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

                if ((tlua->flags & DATATYPE_HTTP_REQUEST_LINE) && tx->request_line != NULL &&
                    bstr_len(tx->request_line) > 0) {
                    lua_pushliteral(tlua->luastate, "http.request_line"); /* stack at -2 */
                    LuaPushStringBuffer(tlua->luastate,
                                     (const uint8_t *)bstr_ptr(tx->request_line),
                                     bstr_len(tx->request_line));
                    lua_settable(tlua->luastate, -3);
                }
            }
        }
    }

    int retval = lua_pcall(tlua->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tlua->luastate, -1));
    }

    /* process returns from script */
    if (lua_gettop(tlua->luastate) > 0) {

        /* script returns a number (return 1 or return 0) */
        if (lua_type(tlua->luastate, 1) == LUA_TNUMBER) {
            double script_ret = lua_tonumber(tlua->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tlua->luastate, 1);

            if (script_ret == 1.0)
                ret = 1;

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
                    if (StringParseInt32(&val, 10, 0,
                                         (const char *)v) < 0) {
                        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value "
                                   "for \"retval\" from LUA return table: '%s'", v);
                        ret = 0;
                    }
                    else if (val == 1) {
                        ret = 1;
                    }
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tlua->luastate, 1);
        }
    }
    while (lua_gettop(tlua->luastate) > 0) {
        lua_pop(tlua->luastate, 1);
    }

    if (lua->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
}

static int DetectLuaAppMatchCommon (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state,
        const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    int ret = 0;
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
                if ((tlua->flags & DATATYPE_HTTP_REQUEST_LINE) && tx->request_line != NULL &&
                    bstr_len(tx->request_line) > 0) {
                    lua_pushliteral(tlua->luastate, "http.request_line"); /* stack at -2 */
                    LuaPushStringBuffer(tlua->luastate,
                                     (const uint8_t *)bstr_ptr(tx->request_line),
                                     bstr_len(tx->request_line));
                    lua_settable(tlua->luastate, -3);
                }
            }
        }
    }

    int retval = lua_pcall(tlua->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tlua->luastate, -1));
    }

    /* process returns from script */
    if (lua_gettop(tlua->luastate) > 0) {

        /* script returns a number (return 1 or return 0) */
        if (lua_type(tlua->luastate, 1) == LUA_TNUMBER) {
            double script_ret = lua_tonumber(tlua->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tlua->luastate, 1);

            if (script_ret == 1.0)
                ret = 1;

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
                    if (StringParseInt32(&val, 10, 0,
                                         (const char *)v) < 0) {
                        SCLogError(SC_ERR_INVALID_VALUE, "Invalid value "
                                   "for \"retval\" from LUA return table: '%s'", v);
                        ret = 0;
                    }
                    else if (val == 1) {
                        ret = 1;
                    }
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tlua->luastate, 1);
        }
    }
    while (lua_gettop(tlua->luastate) > 0) {
        lua_pop(tlua->luastate, 1);
    }

    if (lua->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
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

    DetectLuaThreadData *t = SCMalloc(sizeof(DetectLuaThreadData));
    if (unlikely(t == NULL)) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't alloc ctx memory");
        return NULL;
    }
    memset(t, 0x00, sizeof(DetectLuaThreadData));

    t->alproto = lua->alproto;
    t->flags = lua->flags;

    t->luastate = LuaGetState();
    if (t->luastate == NULL) {
        SCLogError(SC_ERR_LUA_ERROR, "luastate pool depleted");
        goto error;
    }

    luaL_openlibs(t->luastate);

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
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(t->luastate, lua->filename);
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't prime file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

    return (void *)t;

error:
    if (t->luastate != NULL)
        LuaReturnState(t->luastate);
    SCFree(t);
    return NULL;
}

static void DetectLuaThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectLuaThreadData *t = (DetectLuaThreadData *)ctx;
        if (t->luastate != NULL)
            LuaReturnState(t->luastate);
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
    lua = SCMalloc(sizeof(DetectLuaData));
    if (unlikely(lua == NULL))
        goto error;

    memset(lua, 0x00, sizeof(DetectLuaData));

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

    lua_State *luastate = luaL_newstate();
    if (luastate == NULL)
        return -1;
    luaL_openlibs(luastate);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#ifdef UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, ld->filename);
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "init");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUA_ERROR, "no init function in script");
        goto error;
    }

    lua_newtable(luastate); /* stack at -1 */
    if (lua_gettop(luastate) == 0 || lua_type(luastate, 2) != LUA_TTABLE) {
        SCLogError(SC_ERR_LUA_ERROR, "no table setup");
        goto error;
    }

    lua_pushliteral(luastate, "script_api_ver"); /* stack at -2 */
    lua_pushnumber (luastate, 1); /* stack at -3 */
    lua_settable(luastate, -3);

    if (lua_pcall(luastate, 1, 1, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't run script 'init' function: %s", lua_tostring(luastate, -1));
        goto error;
    }

    /* process returns from script */
    if (lua_gettop(luastate) == 0) {
        SCLogError(SC_ERR_LUA_ERROR, "init function in script should return table, nothing returned");
        goto error;
    }
    if (lua_type(luastate, 1) != LUA_TTABLE) {
        SCLogError(SC_ERR_LUA_ERROR, "init function in script should return table, returned is not table");
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

                    if (ld->flowvars == DETECT_LUAJIT_MAX_FLOWVARS) {
                        SCLogError(SC_ERR_LUA_ERROR, "too many flowvars registered");
                        goto error;
                    }

                    uint32_t idx = VarNameStoreSetupAdd((char *)value, VAR_TYPE_FLOW_VAR);
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

                    if (ld->flowints == DETECT_LUAJIT_MAX_FLOWINTS) {
                        SCLogError(SC_ERR_LUA_ERROR, "too many flowints registered");
                        goto error;
                    }

                    uint32_t idx = VarNameStoreSetupAdd((char *)value, VAR_TYPE_FLOW_INT);
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

                    if (ld->bytevars == DETECT_LUAJIT_MAX_BYTEVARS) {
                        SCLogError(SC_ERR_LUA_ERROR, "too many bytevars registered");
                        goto error;
                    }

                    DetectByteIndexType idx;
                    if (!DetectByteRetrieveSMVar(value, s, &idx)) {
                        SCLogError(SC_ERR_LUA_ERROR,
                                "Unknown byte_extract or byte_math var "
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
            ld->flags |= DATATYPE_PACKET;
        } else if (strcmp(k, "payload") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= DATATYPE_PAYLOAD;
        } else if (strcmp(k, "buffer") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= DATATYPE_BUFFER;

            ld->buffername = SCStrdup("buffer");
            if (ld->buffername == NULL) {
                SCLogError(SC_ERR_LUA_ERROR, "alloc error");
                goto error;
            }
        } else if (strcmp(k, "stream") == 0 && strcmp(v, "true") == 0) {
            ld->flags |= DATATYPE_STREAM;

            ld->buffername = SCStrdup("stream");
            if (ld->buffername == NULL) {
                SCLogError(SC_ERR_LUA_ERROR, "alloc error");
                goto error;
            }

        } else if (strncmp(k, "http", 4) == 0 && strcmp(v, "true") == 0) {
            if (ld->alproto != ALPROTO_UNKNOWN && ld->alproto != ALPROTO_HTTP1) {
                SCLogError(SC_ERR_LUA_ERROR, "can just inspect script against one app layer proto like HTTP at a time");
                goto error;
            }
            if (ld->flags != 0) {
                SCLogError(SC_ERR_LUA_ERROR, "when inspecting HTTP buffers only a single buffer can be inspected");
                goto error;
            }

            /* http types */
            ld->alproto = ALPROTO_HTTP1;

            if (strcmp(k, "http.uri") == 0)
                ld->flags |= DATATYPE_HTTP_URI;

            else if (strcmp(k, "http.uri.raw") == 0)
                ld->flags |= DATATYPE_HTTP_URI_RAW;

            else if (strcmp(k, "http.request_line") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_LINE;

            else if (strcmp(k, "http.request_headers") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_HEADERS;

            else if (strcmp(k, "http.request_headers.raw") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_HEADERS_RAW;

            else if (strcmp(k, "http.request_cookie") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_COOKIE;

            else if (strcmp(k, "http.request_user_agent") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_UA;

            else if (strcmp(k, "http.request_body") == 0)
                ld->flags |= DATATYPE_HTTP_REQUEST_BODY;

            else if (strcmp(k, "http.response_body") == 0)
                ld->flags |= DATATYPE_HTTP_RESPONSE_BODY;

            else if (strcmp(k, "http.response_cookie") == 0)
                ld->flags |= DATATYPE_HTTP_RESPONSE_COOKIE;

            else if (strcmp(k, "http.response_headers") == 0)
                ld->flags |= DATATYPE_HTTP_RESPONSE_HEADERS;

            else if (strcmp(k, "http.response_headers.raw") == 0)
                ld->flags |= DATATYPE_HTTP_RESPONSE_HEADERS_RAW;

            else {
                SCLogError(SC_ERR_LUA_ERROR, "unsupported http data type %s", k);
                goto error;
            }

            ld->buffername = SCStrdup(k);
            if (ld->buffername == NULL) {
                SCLogError(SC_ERR_LUA_ERROR, "alloc error");
                goto error;
            }
        } else if (strncmp(k, "dns", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_DNS;

            if (strcmp(k, "dns.rrname") == 0)
                ld->flags |= DATATYPE_DNS_RRNAME;
            else if (strcmp(k, "dns.request") == 0)
                ld->flags |= DATATYPE_DNS_REQUEST;
            else if (strcmp(k, "dns.response") == 0)
                ld->flags |= DATATYPE_DNS_RESPONSE;

            else {
                SCLogError(SC_ERR_LUA_ERROR, "unsupported dns data type %s", k);
                goto error;
            }
            ld->buffername = SCStrdup(k);
            if (ld->buffername == NULL) {
                SCLogError(SC_ERR_LUA_ERROR, "alloc error");
                goto error;
            }
        } else if (strncmp(k, "tls", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_TLS;

            ld->flags |= DATATYPE_TLS;

        } else if (strncmp(k, "ssh", 3) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_SSH;

            ld->flags |= DATATYPE_SSH;

        } else if (strncmp(k, "smtp", 4) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_SMTP;

            ld->flags |= DATATYPE_SMTP;

        } else if (strncmp(k, "dnp3", 4) == 0 && strcmp(v, "true") == 0) {

            ld->alproto = ALPROTO_DNP3;

            ld->flags |= DATATYPE_DNP3;

        } else {
            SCLogError(SC_ERR_LUA_ERROR, "unsupported data type %s", k);
            goto error;
        }
    }

    /* pop the table */
    lua_pop(luastate, 1);
    lua_close(luastate);
    return 0;
error:
    lua_close(luastate);
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
    SigMatch *sm = NULL;

    lua = DetectLuaParse(de_ctx, str);
    if (lua == NULL)
        goto error;

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
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_LUA;
    sm->ctx = (SigMatchCtx *)lua;

    int list = -1;
    if (lua->alproto == ALPROTO_UNKNOWN) {
        if (lua->flags & DATATYPE_STREAM)
            list = DETECT_SM_LIST_PMATCH;
        else {
            if (lua->flags & DATATYPE_BUFFER) {
                if (DetectBufferGetActiveList(de_ctx, s) != -1) {
                    list = s->init_data->list;
                } else {
                    SCLogError(SC_ERR_LUA_ERROR, "Lua and sticky buffer failure");
                    goto error;
                }
            } else
                list = DETECT_SM_LIST_MATCH;
        }

    } else if (lua->alproto == ALPROTO_HTTP1) {
        if (lua->flags & DATATYPE_HTTP_RESPONSE_BODY) {
            list = DetectBufferTypeGetByName("file_data");
        } else if (lua->flags & DATATYPE_HTTP_REQUEST_BODY) {
            list = DetectBufferTypeGetByName("http_client_body");
        } else if (lua->flags & DATATYPE_HTTP_URI) {
            list = DetectBufferTypeGetByName("http_uri");
        } else if (lua->flags & DATATYPE_HTTP_URI_RAW) {
            list = DetectBufferTypeGetByName("http_raw_uri");
        } else if (lua->flags & DATATYPE_HTTP_REQUEST_COOKIE ||
                 lua->flags & DATATYPE_HTTP_RESPONSE_COOKIE)
        {
            list = DetectBufferTypeGetByName("http_cookie");
        } else if (lua->flags & DATATYPE_HTTP_REQUEST_UA) {
            list = DetectBufferTypeGetByName("http_user_agent");
        } else if (lua->flags & (DATATYPE_HTTP_REQUEST_HEADERS|DATATYPE_HTTP_RESPONSE_HEADERS)) {
            list = DetectBufferTypeGetByName("http_header");
        } else if (lua->flags & (DATATYPE_HTTP_REQUEST_HEADERS_RAW|DATATYPE_HTTP_RESPONSE_HEADERS_RAW)) {
            list = DetectBufferTypeGetByName("http_raw_header");
        } else {
            list = DetectBufferTypeGetByName("http_request_line");
        }
    } else if (lua->alproto == ALPROTO_DNS) {
        if (lua->flags & DATATYPE_DNS_RRNAME) {
            list = DetectBufferTypeGetByName("dns_query");
        } else if (lua->flags & DATATYPE_DNS_REQUEST) {
            list = DetectBufferTypeGetByName("dns_request");
        } else if (lua->flags & DATATYPE_DNS_RESPONSE) {
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
        SCLogError(SC_ERR_LUA_ERROR, "lua can't be used with protocol %s",
                   AppLayerGetProtoName(lua->alproto));
        goto error;
    }

    if (list == -1) {
        SCLogError(SC_ERR_LUA_ERROR, "lua can't be used with protocol %s",
                   AppLayerGetProtoName(lua->alproto));
        goto error;
    }

    SigMatchAppendSMToList(s, sm, list);

    return 0;

error:
    if (lua != NULL)
        DetectLuaFree(de_ctx, lua);
    if (sm != NULL)
        SCFree(sm);
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

        DetectUnregisterThreadCtxFuncs(de_ctx, lua, "lua");

        SCFree(lua);
    }
}

#ifdef UNITTESTS
/** \test http buffer */
static int LuaMatchTest01(void)
{
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogDebug("inspecting p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogDebug("inspecting p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogDebug("inspecting p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogDebug("inspecting p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(httpbuf1, httplen1, IPPROTO_TCP);
    p2 = UTHBuildPacket(httpbuf2, httplen2, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* do detect for p1 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1 but should have: ");
        goto end;
    }

    /* do detect for p2 */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_str.value_len != 1) {
        printf("%u != %u: ", fv->data.fv_str.value_len, 1);
        goto end;
    }

    if (memcmp(fv->data.fv_str.value, "2", 1) != 0) {
        PrintRawDataFp(stdout, fv->data.fv_str.value, fv->data.fv_str.value_len);

        printf("buffer mismatch: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n"
                         "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] = "POST / HTTP/1.1\r\n"
                         "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 2) {
        printf("%u != %u: ", fv->data.fv_int.value, 2);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 2) {
        printf("%u != %u: ", fv->data.fv_int.value, 2);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 2) {
        printf("%u != %u: ", fv->data.fv_int.value, 2);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 2) {
        printf("%u != %u: ", fv->data.fv_int.value, 2);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 0) {
        printf("%u != %u: ", fv->data.fv_int.value, 0);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
    int result = 0;
    uint8_t httpbuf1[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.emergingthreats.net\r\n\r\n";
    uint8_t httpbuf2[] =
        "POST / HTTP/1.1\r\n"
        "Host: www.openinfosecfoundation.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Flow f;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    ut_script = script;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, sig);
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    HtpState *http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect for p1 */
    SCLogInfo("p1");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should not have: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect for p2 */
    SCLogInfo("p2");
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    FlowVar *fv = FlowVarGet(&f, 1);
    if (fv == NULL) {
        printf("no flowvar: ");
        goto end;
    }

    if (fv->data.fv_int.value != 0) {
        printf("%u != %u: ", fv->data.fv_int.value, 0);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
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
#endif /* HAVE_LUAJIT */
