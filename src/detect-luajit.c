/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "detect-luajit.h"
#include "detect-luajit-extensions.h"

#include "queue.h"
#include "util-cpu.h"
#include "util-var-name.h"

#ifndef HAVE_LUA

static int DetectLuajitSetupNoSupport (DetectEngineCtx *a, Signature *b, char *c)
{
    SCLogError(SC_ERR_NO_LUAJIT_SUPPORT, "no LuaJIT support built in, needed for luajit keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: luajit
 */
void DetectLuajitRegister(void)
{
    sigmatch_table[DETECT_LUAJIT].name = "luajit";
    sigmatch_table[DETECT_LUAJIT].alias = "lua";
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetupNoSupport;
    sigmatch_table[DETECT_LUAJIT].Free  = NULL;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = NULL;
    sigmatch_table[DETECT_LUAJIT].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering luajit rule option");
    return;
}

#else /* HAVE_LUA */

#ifdef HAVE_LUAJIT
#include "util-pool.h"

/** \brief lua_State pool
 *
 *  Luajit requires states to be alloc'd in memory <2GB. For this reason we
 *  prealloc the states early during engine startup so we have a better chance
 *  of getting the states. We protect the pool with a lock as the detect
 *  threads access it during their init and cleanup.
 *
 *  Pool size is automagically determined based on number of keyword occurences,
 *  cpus/cores and rule reloads being enabled or not.
 *
 *  Alternatively, the "detect-engine.luajit-states" var can be set.
 */
static Pool *luajit_states = NULL;
static pthread_mutex_t luajit_states_lock = SCMUTEX_INITIALIZER;

#endif /* HAVE_LUAJIT */

#include "util-lua.h"

static int DetectLuajitMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, SigMatch *);
static int DetectLuajitSetup (DetectEngineCtx *, Signature *, char *);
static void DetectLuajitRegisterTests(void);
static void DetectLuajitFree(void *);

/**
 * \brief Registration function for keyword: luajit
 */
void DetectLuajitRegister(void)
{
    sigmatch_table[DETECT_LUAJIT].name = "luajit";
    sigmatch_table[DETECT_LUAJIT].alias = "lua";
    sigmatch_table[DETECT_LUAJIT].desc = "match via a luajit script";
    sigmatch_table[DETECT_LUAJIT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Lua_scripting";
    sigmatch_table[DETECT_LUAJIT].Match = DetectLuajitMatch;
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetup;
    sigmatch_table[DETECT_LUAJIT].Free  = DetectLuajitFree;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = DetectLuajitRegisterTests;

	SCLogDebug("registering luajit rule option");
    return;
}

#define DATATYPE_PACKET                     (1<<0)
#define DATATYPE_PAYLOAD                    (1<<1)
#define DATATYPE_STREAM                     (1<<2)

#define DATATYPE_HTTP_URI                   (1<<3)
#define DATATYPE_HTTP_URI_RAW               (1<<4)

#define DATATYPE_HTTP_REQUEST_HEADERS       (1<<5)
#define DATATYPE_HTTP_REQUEST_HEADERS_RAW   (1<<6)
#define DATATYPE_HTTP_REQUEST_COOKIE        (1<<7)
#define DATATYPE_HTTP_REQUEST_UA            (1<<8)

#define DATATYPE_HTTP_REQUEST_LINE          (1<<9)
#define DATATYPE_HTTP_REQUEST_BODY          (1<<10)

#define DATATYPE_HTTP_RESPONSE_COOKIE       (1<<11)
#define DATATYPE_HTTP_RESPONSE_BODY         (1<<12)

#define DATATYPE_HTTP_RESPONSE_HEADERS      (1<<13)
#define DATATYPE_HTTP_RESPONSE_HEADERS_RAW  (1<<14)

#ifdef HAVE_LUAJIT
static void *LuaStatePoolAlloc(void)
{
    return luaL_newstate();
}

static void LuaStatePoolFree(void *d)
{
    lua_State *s = (lua_State *)d;
    if (s != NULL)
        lua_close(s);
}

/** \brief Populate lua states pool
 *
 *  \param num keyword instances
 *  \param reloads bool indicating we have rule reloads enabled
 */
int DetectLuajitSetupStatesPool(int num, int reloads)
{
    int retval = 0;
    pthread_mutex_lock(&luajit_states_lock);

    if (luajit_states == NULL) {
        int cnt = 0;
        char *conf_val = NULL;

        if ((ConfGet("detect-engine.luajit-states", &conf_val)) == 1) {
            cnt = (int)atoi(conf_val);
        } else {
            int cpus = UtilCpuGetNumProcessorsOnline();
            if (cpus == 0) {
                cpus = 10;
            }
            cnt = num * cpus;
            cnt *= 3; /* assume 3 threads per core */

            /* alloc a bunch extra so reload can add new rules/instances */
            if (reloads)
                cnt *= 5;
        }

        luajit_states = PoolInit(0, cnt, 0, LuaStatePoolAlloc, NULL, NULL, NULL, LuaStatePoolFree);
        if (luajit_states == NULL) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "luastate pool init failed, luajit keywords won't work");
            retval = -1;
        }
    }

    pthread_mutex_unlock(&luajit_states_lock);
    return retval;
}
#endif /* HAVE_LUAJIT */

static lua_State *DetectLuajitGetState(void)
{

    lua_State *s = NULL;
#ifdef HAVE_LUAJIT
    pthread_mutex_lock(&luajit_states_lock);
    if (luajit_states != NULL)
        s = (lua_State *)PoolGet(luajit_states);
    pthread_mutex_unlock(&luajit_states_lock);
#else
    s = luaL_newstate();
#endif
    return s;
}

static void DetectLuajitReturnState(lua_State *s)
{
    if (s != NULL) {
#ifdef HAVE_LUAJIT
        pthread_mutex_lock(&luajit_states_lock);
        PoolReturn(luajit_states, (void *)s);
        pthread_mutex_unlock(&luajit_states_lock);
#else
        lua_close(s);
#endif
    }
}

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

int DetectLuajitMatchBuffer(DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm,
        uint8_t *buffer, uint32_t buffer_len, uint32_t offset,
        Flow *f, int flow_lock)
{
    SCEnter();
    int ret = 0;

    if (buffer == NULL || buffer_len == 0)
        SCReturnInt(0);

    DetectLuajitData *luajit = (DetectLuajitData *)sm->ctx;
    if (luajit == NULL)
        SCReturnInt(0);

    DetectLuajitThreadData *tluajit = (DetectLuajitThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, luajit->thread_ctx_id);
    if (tluajit == NULL)
        SCReturnInt(0);

    /* setup extension data for use in lua c functions */
    LuajitExtensionsMatchSetup(tluajit->luastate, luajit, det_ctx, f, flow_lock);

    /* prepare data to pass to script */
    lua_getglobal(tluajit->luastate, "match");
    lua_newtable(tluajit->luastate); /* stack at -1 */

    lua_pushliteral (tluajit->luastate, "offset"); /* stack at -2 */
    lua_pushnumber (tluajit->luastate, (int)(offset + 1));
    lua_settable(tluajit->luastate, -3);

    lua_pushstring (tluajit->luastate, luajit->buffername); /* stack at -2 */
    if (buffer_len % 4) {
        size_t tmpbuflen = buffer_len + (buffer_len % 4);
        uint8_t tmpbuf[tmpbuflen];
        memset(tmpbuf, 0x00, tmpbuflen);
        memcpy(tmpbuf, buffer, buffer_len);
        tmpbuf[buffer_len] = '\0';
        lua_pushlstring (tluajit->luastate, (const char *)tmpbuf, (size_t)buffer_len);
    } else {
        lua_pushlstring (tluajit->luastate, (const char *)buffer, (size_t)buffer_len);
    }
    lua_settable(tluajit->luastate, -3);

    int retval = lua_pcall(tluajit->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tluajit->luastate, -1));
    }

    /* process returns from script */
    if (lua_gettop(tluajit->luastate) > 0) {
        /* script returns a number (return 1 or return 0) */
        if (lua_type(tluajit->luastate, 1) == LUA_TNUMBER) {
            double script_ret = lua_tonumber(tluajit->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tluajit->luastate, 1);

            if (script_ret == 1.0)
                ret = 1;

        /* script returns a table */
        } else if (lua_type(tluajit->luastate, 1) == LUA_TTABLE) {
            lua_pushnil(tluajit->luastate);
            const char *k, *v;
            while (lua_next(tluajit->luastate, -2)) {
                v = lua_tostring(tluajit->luastate, -1);
                lua_pop(tluajit->luastate, 1);
                k = lua_tostring(tluajit->luastate, -1);

                if (!k || !v)
                    continue;

                SCLogDebug("k='%s', v='%s'", k, v);

                if (strcmp(k, "retval") == 0) {
                    if (atoi(v) == 1)
                        ret = 1;
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tluajit->luastate, 1);
        }
    } else {
        SCLogDebug("no stack");
    }

    /* clear the stack */
    while (lua_gettop(tluajit->luastate) > 0) {
        lua_pop(tluajit->luastate, 1);
    }

    if (luajit->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);

}

/**
 * \brief match the specified luajit
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param p packet
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectLuajitData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectLuajitMatch (ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Packet *p, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectLuajitData *luajit = (DetectLuajitData *)m->ctx;
    if (luajit == NULL)
        SCReturnInt(0);

    DetectLuajitThreadData *tluajit = (DetectLuajitThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, luajit->thread_ctx_id);
    if (tluajit == NULL)
        SCReturnInt(0);

    /* setup extension data for use in lua c functions */
    LuajitExtensionsMatchSetup(tluajit->luastate, luajit, det_ctx, p->flow, /* flow not locked */LUA_FLOW_NOT_LOCKED_BY_PARENT);

    if ((tluajit->flags & DATATYPE_PAYLOAD) && p->payload_len == 0)
        SCReturnInt(0);
    if ((tluajit->flags & DATATYPE_PACKET) && GET_PKT_LEN(p) == 0)
        SCReturnInt(0);
    if (tluajit->alproto != ALPROTO_UNKNOWN) {
        if (p->flow == NULL)
            SCReturnInt(0);

        FLOWLOCK_RDLOCK(p->flow);
        int alproto = p->flow->alproto;
        FLOWLOCK_UNLOCK(p->flow);

        if (tluajit->alproto != alproto)
            SCReturnInt(0);
    }

    lua_getglobal(tluajit->luastate, "match");
    lua_newtable(tluajit->luastate); /* stack at -1 */

    if ((tluajit->flags & DATATYPE_PAYLOAD) && p->payload_len) {
        lua_pushliteral(tluajit->luastate, "payload"); /* stack at -2 */
        lua_pushlstring (tluajit->luastate, (const char *)p->payload, (size_t)p->payload_len); /* stack at -3 */
        lua_settable(tluajit->luastate, -3);
    }
    if ((tluajit->flags & DATATYPE_PACKET) && GET_PKT_LEN(p)) {
        lua_pushliteral(tluajit->luastate, "packet"); /* stack at -2 */
        lua_pushlstring (tluajit->luastate, (const char *)GET_PKT_DATA(p), (size_t)GET_PKT_LEN(p)); /* stack at -3 */
        lua_settable(tluajit->luastate, -3);
    }
    if (tluajit->alproto == ALPROTO_HTTP) {
        FLOWLOCK_RDLOCK(p->flow);
        HtpState *htp_state = p->flow->alstate;
        if (htp_state != NULL && htp_state->connp != NULL) {
            htp_tx_t *tx = NULL;
            uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser,
                                                                 STREAM_TOSERVER);
            uint64_t total_txs= AppLayerParserGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, htp_state);
            for ( ; idx < total_txs; idx++) {
                tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, idx);
                if (tx == NULL)
                    continue;

                if ((tluajit->flags & DATATYPE_HTTP_REQUEST_LINE) && tx->request_line != NULL &&
                    bstr_len(tx->request_line) > 0) {
                    lua_pushliteral(tluajit->luastate, "http.request_line"); /* stack at -2 */
                    lua_pushlstring (tluajit->luastate,
                                     (const char *)bstr_ptr(tx->request_line),
                                     bstr_len(tx->request_line));
                    lua_settable(tluajit->luastate, -3);
                }
            }
        }
        FLOWLOCK_UNLOCK(p->flow);
    }

    int retval = lua_pcall(tluajit->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tluajit->luastate, -1));
    }

    /* process returns from script */
    if (lua_gettop(tluajit->luastate) > 0) {

        /* script returns a number (return 1 or return 0) */
        if (lua_type(tluajit->luastate, 1) == LUA_TNUMBER) {
            double script_ret = lua_tonumber(tluajit->luastate, 1);
            SCLogDebug("script_ret %f", script_ret);
            lua_pop(tluajit->luastate, 1);

            if (script_ret == 1.0)
                ret = 1;

        /* script returns a table */
        } else if (lua_type(tluajit->luastate, 1) == LUA_TTABLE) {
            lua_pushnil(tluajit->luastate);
            const char *k, *v;
            while (lua_next(tluajit->luastate, -2)) {
                v = lua_tostring(tluajit->luastate, -1);
                lua_pop(tluajit->luastate, 1);
                k = lua_tostring(tluajit->luastate, -1);

                if (!k || !v)
                    continue;

                SCLogDebug("k='%s', v='%s'", k, v);

                if (strcmp(k, "retval") == 0) {
                    if (atoi(v) == 1)
                        ret = 1;
                } else {
                    /* set flow var? */
                }
            }

            /* pop the table */
            lua_pop(tluajit->luastate, 1);
        }
    }
    while (lua_gettop(tluajit->luastate) > 0) {
        lua_pop(tluajit->luastate, 1);
    }

    if (luajit->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
}

#ifdef UNITTESTS
/* if this ptr is set the luajit setup functions will use this buffer as the
 * lua script instead of calling luaL_loadfile on the filename supplied. */
static const char *ut_script = NULL;
#endif

static void *DetectLuajitThreadInit(void *data)
{
    int status;
    DetectLuajitData *luajit = (DetectLuajitData *)data;
    BUG_ON(luajit == NULL);

    DetectLuajitThreadData *t = SCMalloc(sizeof(DetectLuajitThreadData));
    if (unlikely(t == NULL)) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't alloc ctx memory");
        return NULL;
    }
    memset(t, 0x00, sizeof(DetectLuajitThreadData));

    t->alproto = luajit->alproto;
    t->flags = luajit->flags;

    t->luastate = DetectLuajitGetState();
    if (t->luastate == NULL) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "luastate pool depleted");
        goto error;
    }

    luaL_openlibs(t->luastate);

    LuajitRegisterExtensions(t->luastate);

    lua_pushinteger(t->luastate, (lua_Integer)(luajit->sid));
    lua_setglobal(t->luastate, "SCRuleSid");
    lua_pushinteger(t->luastate, (lua_Integer)(luajit->rev));
    lua_setglobal(t->luastate, "SCRuleRev");
    lua_pushinteger(t->luastate, (lua_Integer)(luajit->gid));
    lua_setglobal(t->luastate, "SCRuleGid");

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#ifdef UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(t->luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(t->luastate, luajit->filename);
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't prime file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

    return (void *)t;

error:
    if (t->luastate != NULL)
        DetectLuajitReturnState(t->luastate);
    SCFree(t);
    return NULL;
}

static void DetectLuajitThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectLuajitThreadData *t = (DetectLuajitThreadData *)ctx;
        if (t->luastate != NULL)
            DetectLuajitReturnState(t->luastate);
        SCFree(t);
    }
}

/**
 * \brief Parse the luajit keyword
 *
 * \param str Pointer to the user provided option
 *
 * \retval luajit pointer to DetectLuajitData on success
 * \retval NULL on failure
 */
static DetectLuajitData *DetectLuajitParse (char *str)
{
    DetectLuajitData *luajit = NULL;

    /* We have a correct luajit option */
    luajit = SCMalloc(sizeof(DetectLuajitData));
    if (unlikely(luajit == NULL))
        goto error;

    memset(luajit, 0x00, sizeof(DetectLuajitData));

    if (strlen(str) && str[0] == '!') {
        luajit->negated = 1;
        str++;
    }

    /* get full filename */
    luajit->filename = DetectLoadCompleteSigPath(str);
    if (luajit->filename == NULL) {
        goto error;
    }

    return luajit;

error:
    if (luajit != NULL)
        DetectLuajitFree(luajit);
    return NULL;
}

static int DetectLuaSetupPrime(DetectEngineCtx *de_ctx, DetectLuajitData *ld)
{
    int status;

    lua_State *luastate = luaL_newstate();
    if (luastate == NULL)
        goto error;
    luaL_openlibs(luastate);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#ifdef UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, ld->filename);
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "init");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no init function in script");
        goto error;
    }

    lua_newtable(luastate); /* stack at -1 */
    if (lua_gettop(luastate) == 0 || lua_type(luastate, 2) != LUA_TTABLE) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no table setup");
        goto error;
    }

    lua_pushliteral(luastate, "script_api_ver"); /* stack at -2 */
    lua_pushnumber (luastate, 1); /* stack at -3 */
    lua_settable(luastate, -3);

    if (lua_pcall(luastate, 1, 1, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't run script 'init' function: %s", lua_tostring(luastate, -1));
        goto error;
    }

    /* process returns from script */
    if (lua_gettop(luastate) == 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "init function in script should return table, nothing returned");
        goto error;
    }
    if (lua_type(luastate, 1) != LUA_TTABLE) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "init function in script should return table, returned is not table");
        goto error;
    }

    lua_pushnil(luastate);
    const char *k, *v;
    while (lua_next(luastate, -2)) {
        k = lua_tostring(luastate, -2);
        if (k == NULL)
            continue;

        /* handle flowvar separately as it has a table as value */
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
                        SCLogError(SC_ERR_LUAJIT_ERROR, "too many flowvars registered");
                        goto error;
                    }

                    uint16_t idx = VariableNameGetIdx(de_ctx, (char *)value, DETECT_FLOWVAR);
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
                        SCLogError(SC_ERR_LUAJIT_ERROR, "too many flowints registered");
                        goto error;
                    }

                    uint16_t idx = VariableNameGetIdx(de_ctx, (char *)value, DETECT_FLOWINT);
                    ld->flowint[ld->flowints++] = idx;
                    SCLogDebug("script uses flowint %u with script id %u", idx, ld->flowints - 1);
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
        } else if (strncmp(k, "http", 4) == 0 && strcmp(v, "true") == 0) {
            if (ld->alproto != ALPROTO_UNKNOWN && ld->alproto != ALPROTO_HTTP) {
                SCLogError(SC_ERR_LUAJIT_ERROR, "can just inspect script against one app layer proto like HTTP at a time");
                goto error;
            }
            if (ld->flags != 0) {
                SCLogError(SC_ERR_LUAJIT_ERROR, "when inspecting HTTP buffers only a single buffer can be inspected");
                goto error;
            }

            /* http types */
            ld->alproto = ALPROTO_HTTP;

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
                SCLogError(SC_ERR_LUAJIT_ERROR, "unsupported http data type %s", k);
                goto error;
            }

            ld->buffername = SCStrdup(k);
            if (ld->buffername == NULL) {
                SCLogError(SC_ERR_LUAJIT_ERROR, "alloc error");
                goto error;
            }

        } else {
            SCLogError(SC_ERR_LUAJIT_ERROR, "unsupported data type %s", k);
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
 * \brief this function is used to parse luajit options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "luajit" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectLuajitSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectLuajitData *luajit = NULL;
    SigMatch *sm = NULL;

    luajit = DetectLuajitParse(str);
    if (luajit == NULL)
        goto error;

    if (DetectLuaSetupPrime(de_ctx, luajit) == -1) {
        goto error;
    }

    luajit->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "luajit",
            DetectLuajitThreadInit, (void *)luajit,
            DetectLuajitThreadFree, 0);
    if (luajit->thread_ctx_id == -1)
        goto error;

    if (luajit->alproto != ALPROTO_UNKNOWN) {
        if (s->alproto != ALPROTO_UNKNOWN && luajit->alproto != s->alproto) {
            goto error;
        }
        s->alproto = luajit->alproto;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_LUAJIT;
    sm->ctx = (void *)luajit;

    if (luajit->alproto == ALPROTO_UNKNOWN)
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    else if (luajit->alproto == ALPROTO_HTTP) {
        if (luajit->flags & DATATYPE_HTTP_RESPONSE_BODY)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HSBDMATCH);
        else if (luajit->flags & DATATYPE_HTTP_REQUEST_BODY)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HCBDMATCH);
        else if (luajit->flags & DATATYPE_HTTP_URI)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_UMATCH);
        else if (luajit->flags & DATATYPE_HTTP_URI_RAW)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HRUDMATCH);
        else if (luajit->flags & DATATYPE_HTTP_REQUEST_COOKIE)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HCDMATCH);
        else if (luajit->flags & DATATYPE_HTTP_REQUEST_UA)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HUADMATCH);
        else if (luajit->flags & (DATATYPE_HTTP_REQUEST_HEADERS|DATATYPE_HTTP_RESPONSE_HEADERS))
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HHDMATCH);
        else if (luajit->flags & (DATATYPE_HTTP_REQUEST_HEADERS_RAW|DATATYPE_HTTP_RESPONSE_HEADERS_RAW))
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HRHDMATCH);
        else if (luajit->flags & DATATYPE_HTTP_RESPONSE_COOKIE)
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HCDMATCH);
        else
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
    } else {
        SCLogError(SC_ERR_LUAJIT_ERROR, "luajit can't be used with protocol %s",
                   AppLayerGetProtoName(luajit->alproto));
        goto error;
    }

    de_ctx->detect_luajit_instances++;
    return 0;

error:
    if (luajit != NULL)
        DetectLuajitFree(luajit);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/** \brief post-sig parse function to set the sid,rev,gid into the
 *         ctx, as this isn't available yet during parsing.
 */
void DetectLuajitPostSetup(Signature *s)
{
    int i;
    SigMatch *sm;

    for (i = 0; i < DETECT_SM_LIST_MAX; i++) {
        for (sm = s->sm_lists[i]; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_LUAJIT)
                continue;

            DetectLuajitData *ld = sm->ctx;
            ld->sid = s->id;
            ld->rev = s->rev;
            ld->gid = s->gid;
        }
    }
}

/**
 * \brief this function will free memory associated with DetectLuajitData
 *
 * \param luajit pointer to DetectLuajitData
 */
static void DetectLuajitFree(void *ptr)
{
    if (ptr != NULL) {
        DetectLuajitData *luajit = (DetectLuajitData *)ptr;

        if (luajit->buffername)
            SCFree(luajit->buffername);
        if (luajit->filename)
            SCFree(luajit->filename);

        SCFree(luajit);
    }
}

#ifdef UNITTESTS
/** \test http buffer */
static int LuajitMatchTest01(void)
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
    char sig[] = "alert http any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test payload buffer */
static int LuajitMatchTest02(void)
{
    const char script[] =
        "function init (args)\n"
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
    char sig[] = "alert tcp any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test packet buffer */
static int LuajitMatchTest03(void)
{
    const char script[] =
        "function init (args)\n"
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
    char sig[] = "alert tcp any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test http buffer, flowints */
static int LuajitMatchTest04(void)
{
    const char script[] =
        "function init (args)\n"
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
    char sig[] = "alert http any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test http buffer, flowints */
static int LuajitMatchTest05(void)
{
    const char script[] =
        "function init (args)\n"
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
    char sig[] = "alert http any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/** \test http buffer, flowints */
static int LuajitMatchTest06(void)
{
    const char script[] =
        "function init (args)\n"
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
    char sig[] = "alert http any any -> any any (flow:to_server; luajit:unittest; sid:1;)";
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
    f.alproto = ALPROTO_HTTP;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

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

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

#endif

void DetectLuajitRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("LuajitMatchTest01", LuajitMatchTest01, 1);
    UtRegisterTest("LuajitMatchTest02", LuajitMatchTest02, 1);
    UtRegisterTest("LuajitMatchTest03", LuajitMatchTest03, 1);
    UtRegisterTest("LuajitMatchTest04", LuajitMatchTest04, 1);
    UtRegisterTest("LuajitMatchTest05", LuajitMatchTest05, 1);
    UtRegisterTest("LuajitMatchTest06", LuajitMatchTest06, 1);
#endif
}

#endif /* HAVE_LUAJIT */

