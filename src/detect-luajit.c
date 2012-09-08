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
    sigmatch_table[DETECT_LUAJIT].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetupNoSupport;
    sigmatch_table[DETECT_LUAJIT].Free  = NULL;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = NULL;

	SCLogDebug("registering luajit rule option");
    return;
}

#else /* HAVE_LUAJIT */

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
    sigmatch_table[DETECT_LUAJIT].Match = DetectLuajitMatch;
    sigmatch_table[DETECT_LUAJIT].Setup = DetectLuajitSetup;
    sigmatch_table[DETECT_LUAJIT].Free  = DetectLuajitFree;
    sigmatch_table[DETECT_LUAJIT].RegisterTests = DetectLuajitRegisterTests;

	SCLogDebug("registering luajit rule option");
    return;
}

#define DATATYPE_PACKET             (1<<0)
#define DATATYPE_PAYLOAD            (1<<1)
#define DATATYPE_STREAM             (1<<2)
#define DATATYPE_HTTP_URI           (1<<3)
#define DATATYPE_HTTP_URI_RAW       (1<<4)
#define DATATYPE_HTTP_REQUEST_LINE  (1<<5)


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
    if (tluajit->alproto != 0) {
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
                    if (tx == NULL || tx->request_uri_normalized == NULL)
                        continue;

                    if ((tluajit->flags & DATATYPE_HTTP_URI) && bstr_len(tx->request_uri_normalized) > 0) {
                        lua_pushliteral(tluajit->luastate, "http.uri"); /* stack at -2 */
                        lua_pushlstring (tluajit->luastate,
                                (const char *)bstr_ptr(tx->request_uri_normalized),
                                bstr_len(tx->request_uri_normalized));
                        lua_settable(tluajit->luastate, -3);
                    }
                    if ((tluajit->flags & DATATYPE_HTTP_REQUEST_LINE) && bstr_len(tx->request_line) > 0) {
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
    DetectLuajitThreadData *t = SCMalloc(sizeof(DetectLuajitThreadData));
    if (t != NULL) {
        memset(t, 0x00, sizeof(DetectLuajitThreadData));

        t->luastate = luaL_newstate();
        BUG_ON(t->luastate == NULL);
        luaL_openlibs(t->luastate);

        int status = luaL_loadfile(t->luastate, (char *)data);
        if (status) {
            fprintf(stderr, "Couldn't load file: %s\n", lua_tostring(t->luastate, -1));
            BUG_ON(1);
        }

        /* prime the script (or something) */
        if (lua_pcall(t->luastate, 0, 0, 0) != 0) {
            fprintf(stderr, "Couldn't prime file: %s\n", lua_tostring(t->luastate, -1));
            BUG_ON(1);
        }

        lua_getglobal(t->luastate, "init");
        if (lua_type(t->luastate, -1) != LUA_TFUNCTION) {
            SCLogInfo("no init function in script");
            /** \todo proper cleanup */
            return NULL;
        }

        lua_newtable(t->luastate); /* stack at -1 */
        if (lua_gettop(t->luastate) == 0 || lua_type(t->luastate, 2) != LUA_TTABLE) {
            SCLogInfo("no table setup");
            /** \todo proper cleanup */
            return NULL;
        }

        lua_pushliteral(t->luastate, "script_api_ver"); /* stack at -2 */
        lua_pushnumber (t->luastate, 1); /* stack at -3 */
        lua_settable(t->luastate, -3);

        if (lua_pcall(t->luastate, 1, 1, 0) != 0) {
            fprintf(stderr, "Couldn't prime file: %s\n", lua_tostring(t->luastate, -1));
            BUG_ON(1);
        }

        /* process returns from script */
        if (lua_gettop(t->luastate) == 0) {
            SCLogInfo("init function in script should return table, nothing returned");
            /** \todo proper cleanup */
            return NULL;
        }
        if (lua_type(t->luastate, 1) != LUA_TTABLE) {
            SCLogInfo("init function in script should return table, returned is not table");
            /** \todo proper cleanup */
            return NULL;
        }

        lua_pushnil(t->luastate);
        const char *k, *v;
        while (lua_next(t->luastate, -2)) {
            v = lua_tostring(t->luastate, -1);
            lua_pop(t->luastate, 1);
            k = lua_tostring(t->luastate, -1);

            if (!k || !v)
                continue;

            SCLogDebug("k='%s', v='%s'", k, v);
            if (strcmp(k, "packet") == 0 && strcmp(v, "true") == 0) {
                t->flags |= DATATYPE_PACKET;
            } else if (strcmp(k, "payload") == 0 && strcmp(v, "true") == 0) {
                t->flags |= DATATYPE_PAYLOAD;
            } else if (strncmp(k, "http", 4) == 0 && strcmp(v, "true") == 0) {
                /* http types */
                t->alproto = ALPROTO_HTTP;

                if (strcmp(k, "http.uri") == 0)
                    t->flags |= DATATYPE_HTTP_URI;
                else if (strcmp(k, "http.request_line") == 0)
                    t->flags |= DATATYPE_HTTP_REQUEST_LINE;
                else {
                    SCLogInfo("unsupported http data type %s", k);
                }

            } else {
                SCLogInfo("unsupported data type %s", k);
            }
        }

        /* pop the table */
        lua_pop(t->luastate, 1);
    }
    return (void *)t;
}

static void DetectLuajitThreadFree(void *ctx) {
    DetectLuajitThreadData *t = (DetectLuajitThreadData *)ctx;

    /** \todo lua state cleanup */

    SCFree(t);
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
    if (luajit == NULL)
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

    luajit->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "luajit",
            DetectLuajitThreadInit, (void *)luajit->filename,
            DetectLuajitThreadFree);
    if (luajit->thread_ctx_id == -1)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_LUAJIT;
    sm->ctx = (void *)luajit;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

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

