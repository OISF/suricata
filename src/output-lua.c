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
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
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

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-lua-http.h"
#include "util-lua-dns.h"
#include "util-lua-tls.h"
#include "util-lua-ssh.h"

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
    LuaStateSetTX(td->lua_ctx->luastate, txptr);
    LuaStateSetFlow(td->lua_ctx->luastate, f, /* locked */LUA_FLOW_LOCKED_BY_PARENT);

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
        LuaStateSetTX(td->lua_ctx->luastate, txptr);
    LuaStateSetFlow(td->lua_ctx->luastate, (Flow *)f, /* locked */LUA_FLOW_LOCKED_BY_PARENT);
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

    char proto[16] = "";
    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
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

        LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
        LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
        LuaStateSetFlow(td->lua_ctx->luastate, p->flow, /* unlocked */LUA_FLOW_NOT_LOCKED_BY_PARENT);
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

static int LuaPacketConditionAlerts(ThreadVars *tv, const Packet *p)
{
    if (p->alerts.cnt > 0)
        return TRUE;
    return FALSE;
}

/** \internal
 *  \brief Packet Logger for lua scripts, for tls
 *
 *  A single call to this function will run one script for a single
 *  packet. If it is called, it means that the registered condition
 *  function has returned TRUE.
 *
 *  The script is called once for each packet.
 */
static int LuaPacketLoggerTls(ThreadVars *tv, void *thread_data, const Packet *p)
{
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&td->lua_ctx->m);

    lua_getglobal(td->lua_ctx->luastate, "log");

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow, /* unlocked */LUA_FLOW_NOT_LOCKED_BY_PARENT);

    int retval = lua_pcall(td->lua_ctx->luastate, 0, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }

    SCMutexUnlock(&td->lua_ctx->m);
    FLOWLOCK_WRLOCK(p->flow);

    SSLState *ssl_state = (SSLState *)FlowGetAppState(p->flow);
    if (ssl_state != NULL)
        ssl_state->flags |= SSL_AL_FLAG_STATE_LOGGED_LUA;

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(0);
}

static int LuaPacketConditionTls(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL) {
        return FALSE;
    }

    if (!(PKT_IS_IPV4(p)) && !(PKT_IS_IPV6(p))) {
        return FALSE;
    }

    if (!(PKT_IS_TCP(p))) {
        return FALSE;
    }

    FLOWLOCK_RDLOCK(p->flow);
    uint16_t proto = FlowGetAppProtocol(p->flow);
    if (proto != ALPROTO_TLS)
        goto dontlog;

    SSLState *ssl_state = (SSLState *)FlowGetAppState(p->flow);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto dontlog;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL)
        goto dontlog;

    /* We only log the state once */
    if (ssl_state->flags & SSL_AL_FLAG_STATE_LOGGED_LUA)
        goto dontlog;

    FLOWLOCK_UNLOCK(p->flow);
    return TRUE;
dontlog:
    FLOWLOCK_UNLOCK(p->flow);
    return FALSE;
}

/** \internal
 *  \brief Packet Logger for lua scripts, for ssh
 *
 *  A single call to this function will run one script for a single
 *  packet. If it is called, it means that the registered condition
 *  function has returned TRUE.
 *
 *  The script is called once for each packet.
 */
static int LuaPacketLoggerSsh(ThreadVars *tv, void *thread_data, const Packet *p)
{
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    SCMutexLock(&td->lua_ctx->m);

    lua_getglobal(td->lua_ctx->luastate, "log");

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow, /* unlocked */LUA_FLOW_NOT_LOCKED_BY_PARENT);

    int retval = lua_pcall(td->lua_ctx->luastate, 0, 0, 0);
    if (retval != 0) {
        SCLogInfo("failed to run script: %s", lua_tostring(td->lua_ctx->luastate, -1));
    }

    SCMutexUnlock(&td->lua_ctx->m);
    FLOWLOCK_WRLOCK(p->flow);

    SshState *ssh_state = (SshState *)FlowGetAppState(p->flow);
    if (ssh_state != NULL)
        ssh_state->cli_hdr.flags |= SSH_FLAG_STATE_LOGGED_LUA;

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(0);
}

static int LuaPacketConditionSsh(ThreadVars *tv, const Packet *p)
{
    if (p->flow == NULL) {
        return FALSE;
    }

    if (!(PKT_IS_IPV4(p)) && !(PKT_IS_IPV6(p))) {
        return FALSE;
    }

    if (!(PKT_IS_TCP(p))) {
        return FALSE;
    }

    FLOWLOCK_RDLOCK(p->flow);
    uint16_t proto = FlowGetAppProtocol(p->flow);
    if (proto != ALPROTO_SSH)
        goto dontlog;

    SshState *ssh_state = (SshState *)FlowGetAppState(p->flow);
    if (ssh_state == NULL) {
        SCLogDebug("no ssh state, so no request logging");
        goto dontlog;
    }

    if (ssh_state->cli_hdr.software_version == NULL ||
        ssh_state->srv_hdr.software_version == NULL)
        goto dontlog;

    /* We only log the state once */
    if (ssh_state->cli_hdr.flags & SSH_FLAG_STATE_LOGGED_LUA)
        goto dontlog;

    FLOWLOCK_UNLOCK(p->flow);
    return TRUE;
dontlog:
    FLOWLOCK_UNLOCK(p->flow);
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

    char proto[16] = "";
    if (SCProtoNameValid(IP_GET_IPPROTO(p)) == TRUE) {
        strlcpy(proto, known_proto[IP_GET_IPPROTO(p)], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "PROTO:%03" PRIu32, IP_GET_IPPROTO(p));
    }

    /* loop through alerts stored in the packet */
    SCMutexLock(&td->lua_ctx->m);
    lua_getglobal(td->lua_ctx->luastate, "log");

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow, /* unlocked */LUA_FLOW_NOT_LOCKED_BY_PARENT);

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

static int LuaPacketCondition(ThreadVars *tv, const Packet *p)
{
    return TRUE;
}

/** \internal
 *  \brief File API Logger function for Lua scripts
 *
 *  Executes a script once for one file.
 *
 * TODO non-http support
 *
 * NOTE p->flow is locked at this point
 */
static int LuaFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff)
{
    SCEnter();
    LogLuaThreadCtx *td = (LogLuaThreadCtx *)thread_data;

    if ((!(PKT_IS_IPV4(p))) && (!(PKT_IS_IPV6(p))))
        return 0;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    /* Get the TX so the script can get more context about it.
     * TODO hardcoded to HTTP currently */
    void *txptr = NULL;
    if (p && p->flow && p->flow->alstate)
        txptr = AppLayerParserGetTx(p->proto, ALPROTO_HTTP, p->flow->alstate, ff->txid);

    SCMutexLock(&td->lua_ctx->m);

    LuaStateSetThreadVars(td->lua_ctx->luastate, tv);
    LuaStateSetPacket(td->lua_ctx->luastate, (Packet *)p);
    LuaStateSetTX(td->lua_ctx->luastate, txptr);
    LuaStateSetFlow(td->lua_ctx->luastate, p->flow, /* locked */LUA_FLOW_LOCKED_BY_PARENT);
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
    LuaStateSetFlow(td->lua_ctx->luastate, f, /* locked */LUA_FLOW_LOCKED_BY_PARENT);

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
    int status;

    lua_State *luastate = luaL_newstate();
    if (luastate == NULL)
        goto error;
    luaL_openlibs(luastate);

    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#if 0//def UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, filename);
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#if 0//def UNITTESTS
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
            options->alproto = ALPROTO_HTTP;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "dns") == 0)
            options->alproto = ALPROTO_DNS;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "tls") == 0)
            options->alproto = ALPROTO_TLS;
        else if (strcmp(k,"protocol") == 0 && strcmp(v, "ssh") == 0)
            options->alproto = ALPROTO_SSH;
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
 *
 *  \retval state Returns the set up luastate on success, NULL on error
 */
static lua_State *LuaScriptSetup(const char *filename)
{
    lua_State *luastate = luaL_newstate();
    if (luastate == NULL) {
        SCLogError(SC_ERR_LUA_ERROR, "luaL_newstate failed");
        goto error;
    }

    luaL_openlibs(luastate);

    int status;
    /* hackish, needed to allow unittests to pass buffers as scripts instead of files */
#if 0//def UNITTESTS
    if (ut_script != NULL) {
        status = luaL_loadbuffer(t->luastate, ut_script, strlen(ut_script), "unittest");
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(t->luastate, -1));
            goto error;
        }
    } else {
#endif
        status = luaL_loadfile(luastate, filename);
        if (status) {
            SCLogError(SC_ERR_LUA_ERROR, "couldn't load file: %s", lua_tostring(luastate, -1));
            goto error;
        }
#if 0//def UNITTESTS
    }
#endif

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
    LuaRegisterTlsFunctions(luastate);
    LuaRegisterSshFunctions(luastate);

    if (lua_pcall(luastate, 0, 0, 0) != 0) {
        SCLogError(SC_ERR_LUA_ERROR, "couldn't run script 'setup' function: %s", lua_tostring(luastate, -1));
        goto error;
    }

    SCLogDebug("lua_State %p is set up", luastate);
    return luastate;
error:
    lua_close(luastate);
    return NULL;
}

/** \brief initialize output for a script instance
 *
 *  Runs script 'setup' function.
 */
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

    const char *dir = "";
    if (parent_ctx && parent_ctx->data) {
        LogLuaMasterCtx *mc = parent_ctx->data;
        dir = mc->path;
    }

    char path[PATH_MAX] = "";
    snprintf(path, sizeof(path),"%s%s%s", dir, strlen(dir) ? "/" : "", conf->val);
    SCLogDebug("script full path %s", path);

    SCMutexLock(&lua_ctx->m);
    lua_ctx->luastate = LuaScriptSetup(path);
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

static void LogLuaMasterFree(OutputCtx *oc) {
    BUG_ON(oc == NULL);
    if (oc->data)
        SCFree(oc->data);
}

/** \internal
 *  \brief initialize output instance for lua module
 *
 *  Parses nested script list, primes them to find out what they
 *  inspect, then fills the OutputCtx::submodules list with the
 *  proper Logger function for the data type the script needs.
 */
static OutputCtx *OutputLuaLogInit(ConfNode *conf)
{
    const char *dir = ConfNodeLookupChildValue(conf, "scripts-dir");
    if (dir == NULL)
        dir = "";

    ConfNode *scripts = ConfNodeLookupChild(conf, "scripts");
    if (scripts == NULL) {
        /* No "outputs" section in the configuration. */
        SCLogInfo("scripts not defined");
        return NULL;
    }

    /* global output ctx setup */
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return NULL;
    }
    output_ctx->data = SCCalloc(1, sizeof(LogLuaMasterCtx));
    if (unlikely(output_ctx->data == NULL)) {
        SCFree(output_ctx);
        return NULL;
    }
    output_ctx->DeInit = LogLuaMasterFree;
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
            SCLogError(SC_ERR_LUA_ERROR, "couldn't initialize scipt");
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

        if (opts.alproto == ALPROTO_HTTP && opts.streaming) {
            om->StreamingLogFunc = LuaStreamingLogger;
            om->alproto = ALPROTO_HTTP;
            AppLayerHtpEnableRequestBodyCallback();
            AppLayerHtpEnableResponseBodyCallback();
        } else if (opts.alproto == ALPROTO_HTTP) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_HTTP;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);
        } else if (opts.alproto == ALPROTO_TLS) {
            om->PacketLogFunc = LuaPacketLoggerTls;
            om->PacketConditionFunc = LuaPacketConditionTls;
        } else if (opts.alproto == ALPROTO_DNS) {
            om->TxLogFunc = LuaTxLogger;
            om->alproto = ALPROTO_DNS;
            AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);
            AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
        } else if (opts.alproto == ALPROTO_SSH) {
            om->PacketLogFunc = LuaPacketLoggerSsh;
            om->PacketConditionFunc = LuaPacketConditionSsh;
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

    return output_ctx;

error:

    if (output_ctx != NULL) {
        if (output_ctx->DeInit && output_ctx->data)
            output_ctx->DeInit(output_ctx->data);
        SCFree(output_ctx);
    }
    return NULL;
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
}

/** \internal
 *  \brief Initialize the thread storage for lua
 *
 *  Currently only stores a pointer to the global LogLuaCtx
 */
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

void TmModuleLuaLogRegister (void) {
    tmm_modules[TMM_LUALOG].name = MODULE_NAME;
    tmm_modules[TMM_LUALOG].ThreadInit = LuaLogThreadInit;
    tmm_modules[TMM_LUALOG].ThreadDeinit = LuaLogThreadDeinit;
    tmm_modules[TMM_LUALOG].RegisterTests = NULL;
    tmm_modules[TMM_LUALOG].cap_flags = 0;
    tmm_modules[TMM_LUALOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterModule(MODULE_NAME, "lua", OutputLuaLogInit);
}

#else

void TmModuleLuaLogRegister (void) {
    /* no-op */
}

#endif
