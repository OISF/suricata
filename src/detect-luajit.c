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
static int DetectLuajitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
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

    lua_getglobal(tluajit->luastate, "match");
    lua_newtable(tluajit->luastate); /* stack at -1 */

    if (p->payload_len) {
        lua_pushliteral(tluajit->luastate, "payload"); /* stack at -2 */
        lua_pushlstring (tluajit->luastate, (const char *)p->payload, (size_t)p->payload_len); /* stack at -3 */
        lua_settable(tluajit->luastate, -3);
    }
    if (GET_PKT_LEN(p)) {
        lua_pushliteral(tluajit->luastate, "packet"); /* stack at -2 */
        lua_pushlstring (tluajit->luastate, (const char *)GET_PKT_DATA(p), (size_t)GET_PKT_LEN(p)); /* stack at -3 */
        lua_settable(tluajit->luastate, -3);
    }

    int retval = lua_pcall(tluajit->luastate, 1, 1, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(tluajit->luastate, -1));
    }

    double script_ret = lua_tonumber(tluajit->luastate, 1);
    SCLogDebug("script_ret %f", script_ret);
    lua_pop(tluajit->luastate, 1);

    if (script_ret == 1.0)
        ret = 1;

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

