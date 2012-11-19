/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "stream-tcp.h"

#include "detect-luajit.h"

#include "queue.h"
#include "util-cpu.h"

#ifndef HAVE_LUAJIT

static int DetectLuajitSetupNoSupport (DetectEngineCtx *a, Signature *b, char *c) {
    SCLogError(SC_ERR_NO_LUAJIT_SUPPORT, "no LuaJIT support built in, needed for luajit keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: luajit
 */
void DetectLuajitRegister(void) {
    sigmatch_table[DETECT_LUAJIT].name = "luajit";
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetupNoSupport;
    sigmatch_table[DETECT_LUAJIT].Free  = NULL;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = NULL;
    sigmatch_table[DETECT_LUAJIT].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering luajit rule option");
    return;
}

#else /* HAVE_LUAJIT */

#include "util-pool.h"

static int DetectLuajitMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, SigMatch *);
static int DetectLuajitSetup (DetectEngineCtx *, Signature *, char *);
static void DetectLuajitRegisterTests(void);
static void DetectLuajitFree(void *);

/**
 * \brief Registration function for keyword: luajit
 */
void DetectLuajitRegister(void) {
    sigmatch_table[DETECT_LUAJIT].name = "luajit";
    sigmatch_table[DETECT_LUAJIT].desc = "match via a luajit script";
    sigmatch_table[DETECT_LUAJIT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Lua_scripting";
    sigmatch_table[DETECT_LUAJIT].Match = DetectLuajitMatch;
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetup;
    sigmatch_table[DETECT_LUAJIT].Free  = DetectLuajitFree;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = DetectLuajitRegisterTests;

	SCLogDebug("registering luajit rule option");
    return;
}

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
static pthread_mutex_t luajit_states_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void *LuaStatePoolAlloc(void) {
    return luaL_newstate();
}

static void LuaStatePoolFree(void *d) {
    lua_State *s = (lua_State *)d;
    if (s != NULL)
        lua_close(s);
}

/** \brief Populate lua states pool
 *
 *  \param num keyword instances
 *  \param reloads bool indicating we have rule reloads enabled
 */
int DetectLuajitSetupStatesPool(int num, int reloads) {
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

static lua_State *DetectLuajitGetState(void) {

    lua_State *s = NULL;
    pthread_mutex_lock(&luajit_states_lock);
    if (luajit_states != NULL)
        s = (lua_State *)PoolGet(luajit_states);
    pthread_mutex_unlock(&luajit_states_lock);
    return s;
}

static void DetectLuajitReturnState(lua_State *s) {
    if (s != NULL) {
        pthread_mutex_lock(&luajit_states_lock);
        PoolReturn(luajit_states, (void *)s);
        pthread_mutex_unlock(&luajit_states_lock);
    }
}

/** \brief dump stack from lua state to screen */
void LuaDumpStack(lua_State *state) {
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

int DetectLuajitMatchBuffer(DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm, uint8_t *buffer, uint32_t buffer_len, uint32_t offset) {
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

    lua_getglobal(tluajit->luastate, "match");
    lua_newtable(tluajit->luastate); /* stack at -1 */

    lua_pushliteral (tluajit->luastate, "offset"); /* stack at -2 */
    lua_pushnumber (tluajit->luastate, (int)(offset + 1));
    lua_settable(tluajit->luastate, -3);

    lua_pushstring (tluajit->luastate, luajit->buffername); /* stack at -2 */
    lua_pushlstring (tluajit->luastate, (const char *)buffer, (size_t)buffer_len);
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
        if (htp_state != NULL && htp_state->connp != NULL && htp_state->connp->conn != NULL) {
            int idx = AppLayerTransactionGetInspectId(p->flow);
            if (idx != -1) {
                htp_tx_t *tx = NULL;

                int size = (int)list_size(htp_state->connp->conn->transactions);
                for ( ; idx < size; idx++)
                {
                    tx = list_get(htp_state->connp->conn->transactions, idx);
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

    if (luajit->negated) {
        if (ret == 1)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
}

static void *DetectLuajitThreadInit(void *data) {
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

    int status = luaL_loadfile(t->luastate, luajit->filename);
    if (status) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
        goto error;
    }

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

static void DetectLuajitThreadFree(void *ctx) {
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

static int DetectLuaSetupPrime(DetectLuajitData *ld) {
    lua_State *luastate = luaL_newstate();
    if (luastate == NULL)
        goto error;
    luaL_openlibs(luastate);

    int status = luaL_loadfile(luastate, ld->filename);
    if (status) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
        goto error;
    }

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
        v = lua_tostring(luastate, -1);
        lua_pop(luastate, 1);
        k = lua_tostring(luastate, -1);
        if (!k || !v)
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

    if (DetectLuaSetupPrime(luajit) == -1) {
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

/**
 * \brief this function will free memory associated with DetectLuajitData
 *
 * \param luajit pointer to DetectLuajitData
 */
static void DetectLuajitFree(void *ptr) {
    if (ptr != NULL) {
        DetectLuajitData *luajit = (DetectLuajitData *)ptr;

        if (luajit->buffername)
            SCFree(luajit->buffername);

        SCFree(luajit);
    }
}

#ifdef UNITTESTS
static int LuajitMatchTest01(void) {
    return 1;
}
#endif

void DetectLuajitRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("LuajitMatchTest01", LuajitMatchTest01, 1);
#endif
}

#endif /* HAVE_LUAJIT */

