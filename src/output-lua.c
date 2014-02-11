/* Copyright (C) 2014 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "output-lua-http.h"

#define MODULE_NAME "LuaLog"

typedef struct LogLuaCtx_ {
    SCMutex m;
    lua_State *luastate;
    int deinit_once;
} LogLuaCtx;

typedef struct LogLuaThreadCtx_ {
    LogLuaCtx *lua_ctx;
} LogLuaThreadCtx;

const char lualog_ext_key_tx[] = "suricata:lualog:tx:ptr";

static int LuaTxLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    SCMutexLock(&td->lua_ctx->m);

    /* we need the tx in our callbacks */
    lua_pushlightuserdata(td->lua_ctx->luastate, (void *)&lualog_ext_key_tx);
    lua_pushlightuserdata(td->lua_ctx->luastate, (void *)txptr);
    lua_settable(td->lua_ctx->luastate, LUA_REGISTRYINDEX);

    /* prepare data to pass to script */
    lua_getglobal(td->lua_ctx->luastate, "log");
    lua_newtable(td->lua_ctx->luastate); /* stack at -1 */
    lua_pushliteral (td->lua_ctx->luastate, "tx_id"); /* stack at -2 */
    lua_pushnumber (td->lua_ctx->luastate, (int)(tx_id));
    lua_settable(td->lua_ctx->luastate, -3);

    int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }

    SCMutexUnlock(&td->lua_ctx->m);
    SCReturnInt(0);
}

/** \brief dump stack from lua state to screen */
void LuaPrintStack(lua_State *state) {
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

/** \brief load and evaluate the script
 *
 *  This function parses the script, checks if all the required functions
 *  are defined and runs the 'init' function. The init function will inform
 *  us what the scripts needs are.
 */
static int LuaScriptInit(const char *filename) {
    int status;
//    AppProto alproto = ALPROTO_UNKNOWN;

    lua_State *luastate = luaL_newstate();
    if (luastate == NULL)
        goto error;
    luaL_openlibs(luastate);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#if 0//def UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, filename);
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#if 0//def UNITTESTS
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

        v = lua_tostring(luastate, -1);
        lua_pop(luastate, 1);
        if (v == NULL)
            continue;

        SCLogDebug("k='%s', v='%s'", k, v);

//        if (strcmp(k,"protocol") == 0 && strcmp(v, "http") == 0)
//            alproto = ALPROTO_HTTP;
    }
    //SCLogInfo("alproto %u", alproto);

    lua_getglobal(luastate, "setup");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no setup function in script");
        goto error;
    }

    lua_getglobal(luastate, "log");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no log function in script");
        goto error;
    }

    lua_getglobal(luastate, "deinit");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no deinit function in script");
        goto error;
    }

    /* pop the table */
    lua_pop(luastate, 1);
    lua_close(luastate);
    return 0;
error:
    lua_close(luastate);
    return -1;
}

/** \brief setup a luastate for use at runtime
 *
 *  This loads the script, primes it and then runs the 'setup' function.
 */
static lua_State *LuaScriptSetup(const char *filename)
{
    lua_State *luastate = luaL_newstate();
    if (luastate == NULL) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "luaL_newstate failed");
        goto error;
    }

    luaL_openlibs(luastate);

    int status;
    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#if 0//def UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(t->luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, filename);
        if (status) {
            SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#if 0//def UNITTESTS
    }
#endif

    /* prime the script (or something) */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "setup");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no init function in script");
        goto error;
    }

    //LuaPrintStack(luastate);
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't run script 'setup' function: %s", lua_tostring(luastate, -1));
        goto error;
    }
    //LuaPrintStack(luastate);

    if (1) { //http
        if (LogLuaRegisterHttpFunctions(luastate) != 0)
            SCLogInfo("boooh!");
    }

    SCLogDebug("lua_State %p is set up", luastate);
    return luastate;
error:
    lua_close(luastate);
    return NULL;
}

static OutputCtx *OutputLuaLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    if (conf == NULL)
        return NULL;

    LogLuaCtx *lua_ctx = SCMalloc(sizeof(LogLuaCtx));
    if (unlikely(lua_ctx == NULL))
        return NULL;
    memset(lua_ctx, 0x00, sizeof(*lua_ctx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(lua_ctx);
        return NULL;
    }

    SCMutexInit(&lua_ctx->m, NULL);

    //    SCLogInfo("script %s", conf->val);

    SCMutexLock(&lua_ctx->m);
    lua_ctx->luastate = LuaScriptSetup(conf->val);
    SCMutexUnlock(&lua_ctx->m);
    if (lua_ctx->luastate == NULL)
        goto error;

    SCLogDebug("lua_ctx %p", lua_ctx);

    output_ctx->data = lua_ctx;
    output_ctx->DeInit = NULL;

    return output_ctx;
error:
    SCMutexDestroy(&lua_ctx->m);
    SCFree(lua_ctx);
    SCFree(output_ctx);
    return NULL;
}

static OutputCtx *OutputLuaLogInit(ConfNode *conf)
{
    ConfNode *scripts = ConfNodeLookupChild(conf, "scripts");
    if (scripts == NULL) {
        /* No "outputs" section in the configuration. */
        SCLogInfo("scripts not defined");
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&output_ctx->submodules);

    ConfNode *script;
    TAILQ_FOREACH(script, &scripts->head, next) {
        SCLogInfo("script %s", script->val);

        int r = LuaScriptInit(script->val);
        if (r != 0) {
            SCLogInfo("script init failed (%d)", r);
            continue;
        }


        OutputModule *om = SCCalloc(1, sizeof(*om));
        BUG_ON(om == NULL); //TODO

        if (1) { // TODO, logger type selection logic
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_HTTP;
            om->name = MODULE_NAME;
            om->conf_name = script->val;
            om->InitSubFunc = OutputLuaLogInitSub;
            TAILQ_INSERT_TAIL(&output_ctx->submodules, om, entries);
        }
    }

    return output_ctx;
}

static void OutputLuaLogDoDeinit(LogLuaCtx *lua_ctx)
{
    lua_State *luastate = lua_ctx->luastate;

    lua_getglobal(luastate, "deinit");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "no deinit function in script");
        return;
    }
    //LuaPrintStack(luastate);

    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUAJIT_ERROR, "couldn't run script 'deinit' function: %s", lua_tostring(luastate, -1));
        return;
    }
}

static TmEcode LuaLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogLuaThreadCtx *td = SCMalloc(sizeof(*td));
    if (unlikely(td == NULL))
        return TM_ECODE_FAILED;
    memset(td, 0, sizeof(*td));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for LuaLog. \"initdata\" argument NULL");
        SCFree(td);
        return TM_ECODE_FAILED;
    }

    LogLuaCtx *lua_ctx = ((OutputCtx *)initdata)->data;
    SCLogDebug("lua_ctx %p", lua_ctx);
    td->lua_ctx = lua_ctx;
    *data = (void *)td;
    return TM_ECODE_OK;
}

static TmEcode LuaLogThreadDeinit(ThreadVars *t, void *data)
{
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)data;
    if (td == NULL) {
        return TM_ECODE_OK;
    }

    SCMutexLock(&td->lua_ctx->m);
    if (td->lua_ctx->deinit_once == 0) {
        OutputLuaLogDoDeinit(td->lua_ctx);
        td->lua_ctx->deinit_once = 1;
    }
    SCMutexUnlock(&td->lua_ctx->m);

    /* clear memory */
    memset(td, 0, sizeof(*td));

    SCFree(td);
    return TM_ECODE_OK;
}

void TmModuleLuaLogRegister (void) {
    tmm_modules[TMM_LUALOG].name = MODULE_NAME;
    tmm_modules[TMM_LUALOG].ThreadInit = LuaLogThreadInit;
    tmm_modules[TMM_LUALOG].ThreadDeinit = LuaLogThreadDeinit;
    tmm_modules[TMM_LUALOG].RegisterTests = NULL;
    tmm_modules[TMM_LUALOG].cap_flags = 0;
    tmm_modules[TMM_LUALOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterModule(MODULE_NAME, "lua", OutputLuaLogInit);
    SCLogInfo("registered");
}

#else

void TmModuleLuaLogRegister (void) {
    /* no-op */
}

#endif
