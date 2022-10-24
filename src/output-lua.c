/* Copyright (C) 2014-2022 Open Information Security Foundation
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
#include "output-lua.h"

#ifdef HAVE_LUA
#include "util-print.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "output.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-http.h"
#include "util-lua-dns.h"
#include "util-lua-ja3.h"
#include "util-lua-tls.h"
#include "util-lua-ssh.h"
#include "util-lua-hassh.h"
#include "util-lua-smtp.h"

#define MODULE_NAME "LuaLog"

/** \brief structure containing global config
 *  The OutputLuaLogInitSub which is run per script
 *  can access this to get global config info through
 *  it's parent_ctx->data ptr.
 */
typedef struct LogLuaMasterCtx_ {
    char path[PATH_MAX]; /**< contains script-dir */
} LogLuaMasterCtx;

typedef struct LogLuaCtx_ {
    SCMutex m;
    lua_State *luastate;
    int deinit_once;
} LogLuaCtx;

typedef struct LogLuaThreadCtx_ {
    LogLuaCtx *lua_ctx;
} LogLuaThreadCtx;

static TmEcode LuaLogThreadInit(ThreadVars *t, const void *initdata, void **data);
static TmEcode LuaLogThreadDeinit(ThreadVars *t, void *data);

/** \internal
 *  \brief TX logger for lua scripts
 *
 * A single call to this function will run one script on a single
 * transaction.
 *
 * NOTE: The flow (f) also referenced by p->flow is locked.
 */
static int LuaTxLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    SCMutexLock(&td->lua_ctx->m);

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetTX(td->lua_ctx->luastate, txptr, tx_id);
    LuaStateSetFlow(td->lua_ctx->luastate, f);

    /* prepare data to pass to script */
    lua_getglobal(td->lua_ctx->luastate, "log");
    lua_newtable(td->lua_ctx->luastate);
    LuaPushTableKeyValueInt(td->lua_ctx->luastate, "tx_id", (int)(tx_id));

    int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }

    SCMutexUnlock(&td->lua_ctx->m);
    SCReturnInt(0);
}

/** \internal
 *  \brief Streaming logger for lua scripts
 *
 *  Hooks into the Streaming Logger API. Gets called for each chunk of new
 *  streaming data.
 */
static int LuaStreamingLogger(ThreadVars *tv, void *thread_data, const Flow *f,
        const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    SCEnter();

    void *txptr = NULL;
    LuaStreamingBuffer b = { data, data_len, flags };

    SCLogDebug("flags %02x", flags);

    if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION) {
        if (f && f->alstate)
            txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
    }

    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    SCMutexLock(&td->lua_ctx->m);

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION)
        LuaStateSetTX(td->lua_ctx->luastate, txptr, tx_id);
    LuaStateSetFlow(td->lua_ctx->luastate, (Flow *)f);
    LuaStateSetStreamingBuffer(td->lua_ctx->luastate, &b);

    /* prepare data to pass to script */
    lua_getglobal(td->lua_ctx->luastate, "log");
    lua_newtable(td->lua_ctx->luastate);

    if (flags & OUTPUT_STREAMING_FLAG_TRANSACTION)
        LuaPushTableKeyValueInt(td->lua_ctx->luastate, "tx_id", (int)(tx_id));

    int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }

    SCMutexUnlock(&td->lua_ctx->m);

    SCReturnInt(TM_ECODE_OK);
}

/** \internal
 *  \brief Packet Logger for lua scripts, for alerts
 *
 *  A single call to this function will run one script for a single
 *  packet. If it is called, it means that the registered condition
 *  function has returned TRUE.
 *
 *  The script is called once for each alert stored in the packet.
 *
 *  NOTE: p->flow is UNlocked
 */
static int LuaPacketLoggerAlerts(ThreadVars *tv, void *thread_data, const Packet *p)
{
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    if (!(PKT_IS_IPV4(p)) && !(PKT_IS_IPV6(p))) {
        /* decoder event */
        goto not_supported;
    }

    /* loop through alerts stored in the packet */
    SCMutexLock(&td->lua_ctx->m);
    uint16_t cnt;
    for (cnt = 0; cnt < p->alerts.cnt; cnt++) {
        const PacketAlert *pa = &p->alerts.alerts[cnt];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        lua_getglobal(td->lua_ctx->luastate, "log");

        void *txptr = NULL;
        if (p->flow && p->flow->alstate && (pa->flags & PACKET_ALERT_FLAG_TX))
            txptr = AppLayerParserGetTx(
                    p->flow->proto, p->flow->alproto, p->flow->alstate, pa->tx_id);

        LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
        LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
        LuaStateSetTX(td->lua_ctx->luastate, txptr, pa->tx_id);
        LuaStateSetFlow(td->lua_ctx->luastate, p->flow);
        LuaStateSetPacketAlert(td->lua_ctx->luastate, (PacketAlert *)pa);

        /* prepare data to pass to script */
        //lua_newtable(td->lua_ctx->luastate);

        int retval = lua_pcall(td->lua_ctx->luastate, 0, 0, 0);
        if (retval != 0) {
            SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
        }
    }
    SCMutexUnlock(&td->lua_ctx->m);
not_supported:
    SCReturnInt(0);
}

static int LuaPacketConditionAlerts(ThreadVars *tv, void *data, const Packet *p)
{
    if (p->alerts.cnt > 0)
        return TRUE;
    return FALSE;
}

/** \internal
 *  \brief Packet Logger for lua scripts, for packets
 *
 *  A single call to this function will run one script for a single
 *  packet. If it is called, it means that the registered condition
 *  function has returned TRUE.
 *
 *  The script is called once for each packet.
 *
 *  NOTE: p->flow is UNlocked
 */
static int LuaPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    char timebuf[64];

    if ((!(PKT_IS_IPV4(p))) && (!(PKT_IS_IPV6(p)))) {
        goto not_supported;
    }

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    /* loop through alerts stored in the packet */
    SCMutexLock(&td->lua_ctx->m);
    lua_getglobal(td->lua_ctx->luastate, "log");

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow);

    /* prepare data to pass to script */
    lua_newtable(td->lua_ctx->luastate);

    int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }
    SCMutexUnlock(&td->lua_ctx->m);
not_supported:
    SCReturnInt(0);
}

static int LuaPacketCondition(ThreadVars *tv, void *data, const Packet *p)
{
    return TRUE;
}

/** \internal
 *  \brief File API Logger function for Lua scripts
 *
 *  Executes a script once for one file.
 *
 * NOTE p->flow is locked at this point
 */
static int LuaFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff,
        void *tx, const uint64_t tx_id, uint8_t dir)
{
    SCEnter();
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    if ((!(PKT_IS_IPV4(p))) && (!(PKT_IS_IPV6(p))))
        return 0;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    SCMutexLock(&td->lua_ctx->m);

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetTX(td->lua_ctx->luastate, tx, tx_id);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow);
    LuaStateSetFile(td->lua_ctx->luastate, (File *)ff);

    /* get the lua function to call */
    lua_getglobal(td->lua_ctx->luastate, "log");

    int retval = lua_pcall(td->lua_ctx->luastate, 0, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }
    SCMutexUnlock(&td->lua_ctx->m);
    return 0;
}

/** \internal
 *  \brief Flow API Logger function for Lua scripts
 *
 *  Executes a script once for one flow
 *
 *  Note: flow 'f' is locked
 */
static int LuaFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    SCLogDebug("f %p", f);

    SCMutexLock(&td->lua_ctx->m);

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetFlow(td->lua_ctx->luastate, f);

    /* get the lua function to call */
    lua_getglobal(td->lua_ctx->luastate, "log");

    int retval = lua_pcall(td->lua_ctx->luastate, 0, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }
    SCMutexUnlock(&td->lua_ctx->m);
    return 0;
}



static int LuaStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st)
{
    SCEnter();
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    SCMutexLock(&td->lua_ctx->m);

    lua_State *luastate = td->lua_ctx->luastate;
    /* get the lua function to call */
    lua_getglobal(td->lua_ctx->luastate, "log");

    /* create lua array, which is really just a table. The key is an int (1-x),
     * the value another table with named fields: name, tm_name, value, pvalue.
     * { 1, { name=<name>, tmname=<tm_name>, value=<value>, pvalue=<pvalue>}}
     * { 2, { name=<name>, tmname=<tm_name>, value=<value>, pvalue=<pvalue>}}
     * etc
     */
    lua_newtable(luastate);
    uint32_t u = 0;
    for (; u < st->nstats; u++) {
        lua_pushinteger(luastate, u + 1);

        lua_newtable(luastate);

        lua_pushstring(luastate, "name");
        lua_pushstring(luastate, st->stats[u].name);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "tmname");
        lua_pushstring(luastate, st->stats[u].tm_name);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "value");
        lua_pushinteger(luastate, st->stats[u].value);
        lua_settable(luastate, -3);

        lua_pushstring(luastate, "pvalue");
        lua_pushinteger(luastate, st->stats[u].pvalue);
        lua_settable(luastate, -3);

        lua_settable(luastate, -3);
    }

    int retval = lua_pcall(td->lua_ctx->luastate, 1, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }
    SCMutexUnlock(&td->lua_ctx->m);
    return 0;

}

typedef struct LogLuaScriptOptions_ {
    AppProto alproto;
    int packet;
    int alerts;
    int file;
    int streaming;
    int tcp_data;
    int http_body;
    int flow;
    int stats;
} LogLuaScriptOptions;

/** \brief load and evaluate the script
 *
 *  This function parses the script, checks if all the required functions
 *  are defined and runs the 'init' function. The init function will inform
 *  us what the scripts needs are.
 *
 *  \param filename filename of lua script file
 *  \param options struct to pass script requirements/options back to caller
 *  \retval errcode 0 ok, -1 error
 */
static int LuaScriptInit(const char *filename, LogLuaScriptOptions *options) {
    lua_State *luastate = LuaGetState();
    if (luastate == NULL)
        goto error;
    luaL_openlibs(luastate);

    int status = luaL_loadfile(luastate, filename);
    if (status) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
        goto error;
    }

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

    lua_pushliteral(luastate, "script_api_ver");
    lua_pushnumber (luastate, 1);
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

        v = lua_tostring(luastate, -1);
        lua_pop(luastate, 1);
        if (v == NULL)
            continue;

        SCLogDebug("k='%s', v='%s'", k, v);

        if (strcmp(k,"protocol") == 0 && strcmp(v, "http") == 0)
            options->alproto = ALPROTO_HTTP1;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "dns") == 0)
            options->alproto = ALPROTO_DNS;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "tls") == 0)
            options->alproto = ALPROTO_TLS;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "ssh") == 0)
            options->alproto = ALPROTO_SSH;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "smtp") == 0)
            options->alproto = ALPROTO_SMTP;
        else if (strcmp(k, "type") == 0 && strcmp(v, "packet") == 0)
            options->packet = 1;
        else if (strcmp(k, "filter") == 0 && strcmp(v, "alerts") == 0)
            options->alerts = 1;
        else if (strcmp(k, "type") == 0 && strcmp(v, "file") == 0)
            options->file = 1;
        else if (strcmp(k, "type") == 0 && strcmp(v, "streaming") == 0)
            options->streaming = 1;
        else if (strcmp(k, "type") == 0 && strcmp(v, "flow") == 0)
            options->flow = 1;
        else if (strcmp(k, "filter") == 0 && strcmp(v, "tcp") == 0)
            options->tcp_data = 1;
        else if (strcmp(k, "type") == 0 && strcmp(v, "stats") == 0)
            options->stats = 1;
        else
            SCLogInfo("unknown key and/or value: k='%s', v='%s'", k, v);
    }

    if (((options->alproto != ALPROTO_UNKNOWN)) + options->packet + options->file > 1) {
        SCLogError(SC_ERR_LUA_ERROR, "invalid combination of 'needs' in the script");
        goto error;
    }

    lua_getglobal(luastate, "setup");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUA_ERROR, "no setup function in script");
        goto error;
    }

    lua_getglobal(luastate, "log");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUA_ERROR, "no log function in script");
        goto error;
    }

    lua_getglobal(luastate, "deinit");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUA_ERROR, "no deinit function in script");
        goto error;
    }

    LuaReturnState(luastate);
    return 0;
error:
    if (luastate)
        LuaReturnState(luastate);
    return -1;
}

/** \brief setup a luastate for use at runtime
 *
 *  This loads the script, primes it and then runs the 'setup' function.
 *
 *  \retval state Returns the set up luastate on success, NULL on error
 */
static lua_State *LuaScriptSetup(const char *filename)
{
    lua_State *luastate = LuaGetState();
    if (luastate == NULL) {
        SCLogError(SC_ERR_LUA_ERROR, "luaL_newstate failed");
        goto error;
    }

    luaL_openlibs(luastate);

    int status = luaL_loadfile(luastate, filename);
    if (status) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    /* prime the script */
    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't prime file: %s", lua_tostring(luastate, -1));
        goto error;
    }

    lua_getglobal(luastate, "setup");

    /* register functions common to all */
    LuaRegisterFunctions(luastate);
    /* unconditionally register http function. They will only work
     * if the tx is registered in the state at runtime though. */
    LuaRegisterHttpFunctions(luastate);
    LuaRegisterDnsFunctions(luastate);
    LuaRegisterJa3Functions(luastate);
    LuaRegisterTlsFunctions(luastate);
    LuaRegisterSshFunctions(luastate);
    LuaRegisterHasshFunctions(luastate);
    LuaRegisterSmtpFunctions(luastate);

    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't run script 'setup' function: %s", lua_tostring(luastate, -1));
        goto error;
    }

    SCLogDebug("lua_State %p is set up", luastate);
    return luastate;
error:
    if (luastate)
        LuaReturnState(luastate);
    return NULL;
}

static void LogLuaSubFree(OutputCtx *oc) {
    if (oc->data)
        SCFree(oc->data);
    SCFree(oc);
}

/** \brief initialize output for a script instance
 *
 *  Runs script 'setup' function.
 */
static OutputInitResult OutputLuaLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    if (conf == NULL)
        return result;

    LogLuaCtx *lua_ctx = SCMalloc(sizeof(LogLuaCtx));
    if (unlikely(lua_ctx == NULL))
        return result;
    memset(lua_ctx, 0x00, sizeof(*lua_ctx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(lua_ctx);
        return result;
    }

    SCMutexInit(&lua_ctx->m, NULL);

    const char *dir = "";
    if (parent_ctx && parent_ctx->data) {
        LogLuaMasterCtx *mc = parent_ctx->data;
        dir = mc->path;
    }

    char path[PATH_MAX] = "";
    int ret = snprintf(path, sizeof(path),"%s%s%s", dir, strlen(dir) ? "/" : "", conf->val);
    if (ret < 0 || ret == sizeof(path)) {
        SCLogError(SC_ERR_SPRINTF,"failed to construct lua script path");
        goto error;
    }
    SCLogDebug("script full path %s", path);

    SCMutexLock(&lua_ctx->m);
    lua_ctx->luastate = LuaScriptSetup(path);
    SCMutexUnlock(&lua_ctx->m);
    if (lua_ctx->luastate == NULL)
        goto error;

    SCLogDebug("lua_ctx %p", lua_ctx);

    output_ctx->data = lua_ctx;
    output_ctx->DeInit = LogLuaSubFree;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
error:
    SCMutexDestroy(&lua_ctx->m);
    SCFree(lua_ctx);
    SCFree(output_ctx);
    return result;
}

static void LogLuaMasterFree(OutputCtx *oc)
{
    if (oc->data)
        SCFree(oc->data);

    OutputModule *om, *tom;
    TAILQ_FOREACH_SAFE(om, &oc->submodules, entries, tom) {
        SCFree(om);
    }
    SCFree(oc);
}

/** \internal
 *  \brief initialize output instance for lua module
 *
 *  Parses nested script list, primes them to find out what they
 *  inspect, then fills the OutputCtx::submodules list with the
 *  proper Logger function for the data type the script needs.
 */
static OutputInitResult OutputLuaLogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    const char *dir = ConfNodeLookupChildValue(conf, "scripts-dir");
    if (dir == NULL)
        dir = "";

    ConfNode *scripts = ConfNodeLookupChild(conf, "scripts");
    if (scripts == NULL) {
        /* No "outputs" section in the configuration. */
        SCLogInfo("scripts not defined");
        return result;
    }

    /* global output ctx setup */
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }
    output_ctx->DeInit = LogLuaMasterFree;
    output_ctx->data = SCCalloc(1, sizeof(LogLuaMasterCtx));
    if (unlikely(output_ctx->data == NULL)) {
        SCFree(output_ctx);
        return result;
    }
    LogLuaMasterCtx *master_config = output_ctx->data;
    strlcpy(master_config->path, dir, sizeof(master_config->path));
    TAILQ_INIT(&output_ctx->submodules);

    /* check the enables scripts and set them up as submodules */
    ConfNode *script;
    TAILQ_FOREACH(script, &scripts->head, next) {
        SCLogInfo("enabling script %s", script->val);
        LogLuaScriptOptions opts;
        memset(&opts, 0x00, sizeof(opts));

        char path[PATH_MAX] = "";
        snprintf(path, sizeof(path),"%s%s%s", dir, strlen(dir) ? "/" : "", script->val);
        SCLogDebug("script full path %s", path);

        int r = LuaScriptInit(path, &opts);
        if (r != 0) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't initialize script");
            goto error;
        }

        /* create an OutputModule for this script, based
         * on it's needs. */
        OutputModule *om = SCCalloc(1, sizeof(*om));
        if (om == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "calloc() failed");
            goto error;
        }

        om->name = MODULE_NAME;
        om->conf_name = script->val;
        om->InitSubFunc = OutputLuaLogInitSub;
        om->ThreadInit = LuaLogThreadInit;
        om->ThreadDeinit = LuaLogThreadDeinit;

        if (opts.alproto == ALPROTO_HTTP1 && opts.streaming) {
            om->StreamingLogFunc = LuaStreamingLogger;
            om->stream_type = STREAMING_HTTP_BODIES;
            om->alproto = ALPROTO_HTTP1;
            AppLayerHtpEnableRequestBodyCallback();
            AppLayerHtpEnableResponseBodyCallback();
        } else if (opts.alproto == ALPROTO_HTTP1) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_HTTP1;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP1);
        } else if (opts.alproto == ALPROTO_TLS) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_TLS;
            om->tc_log_progress = TLS_HANDSHAKE_DONE;
            om->ts_log_progress = TLS_HANDSHAKE_DONE;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);
        } else if (opts.alproto == ALPROTO_DNS) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_DNS;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);
            AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
        } else if (opts.alproto == ALPROTO_SSH) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_SSH;
            om->TxLogCondition = SSHTxLogCondition;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SSH);
        } else if (opts.alproto == ALPROTO_SMTP) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_SMTP;
            om->ts_log_progress = -1;
            om->tc_log_progress = -1;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMTP);
        } else if (opts.packet && opts.alerts) {
            om->PacketLogFunc = LuaPacketLoggerAlerts;
            om->PacketConditionFunc = LuaPacketConditionAlerts;
        } else if (opts.packet && opts.alerts == 0) {
            om->PacketLogFunc = LuaPacketLogger;
            om->PacketConditionFunc = LuaPacketCondition;
        } else if (opts.file) {
            om->FileLogFunc = LuaFileLogger;
            AppLayerHtpNeedFileInspection();
        } else if (opts.streaming && opts.tcp_data) {
            om->StreamingLogFunc = LuaStreamingLogger;
            om->stream_type = STREAMING_TCP_DATA;
        } else if (opts.flow) {
            om->FlowLogFunc = LuaFlowLogger;
        } else if (opts.stats) {
            om->StatsLogFunc = LuaStatsLogger;
        } else {
            SCLogError(SC_ERR_LUA_ERROR, "failed to setup thread module");
            SCFree(om);
            goto error;
        }

        TAILQ_INSERT_TAIL(&output_ctx->submodules, om, entries);
    }

    result.ctx = output_ctx;
    result.ok = true;
    return result;

error:
    if (output_ctx->DeInit)
        output_ctx->DeInit(output_ctx);

    int failure_fatal = 0;
    if (ConfGetBool("engine.init-failure-fatal", &failure_fatal) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }
    if (failure_fatal) {
                   FatalError(SC_ERR_FATAL,
                              "Error during setup of lua output. Details should be "
                              "described in previous error messages. Shutting down...");
    }

    return result;
}

/** \internal
 *  \brief Run the scripts 'deinit' function
 */
static void OutputLuaLogDoDeinit(LogLuaCtx *lua_ctx)
{
    lua_State *luastate = lua_ctx->luastate;

    lua_getglobal(luastate, "deinit");
    if (lua_type(luastate, -1) != LUA_TFUNCTION) {
        SCLogError(SC_ERR_LUA_ERROR, "no deinit function in script");
        return;
    }
    //LuaPrintStack(luastate);

    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't run script 'deinit' function: %s", lua_tostring(luastate, -1));
        return;
    }
    LuaReturnState(luastate);
}

/** \internal
 *  \brief Initialize the thread storage for lua
 *
 *  Currently only stores a pointer to the global LogLuaCtx
 */
static TmEcode LuaLogThreadInit(ThreadVars *t, const void *initdata, void **data)
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

/** \internal
 *  \brief Deinit the thread storage for lua
 *
 *  Calls OutputLuaLogDoDeinit if no-one else already did.
 */
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

void LuaLogRegister(void) {
    /* register as separate module */
    OutputRegisterModule(MODULE_NAME, "lua", OutputLuaLogInit);
}

#else /* HAVE_LUA */

void LuaLogRegister (void) {
    /* no-op */
}

#endif /* HAVE_LUA */
