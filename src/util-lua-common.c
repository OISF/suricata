/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * Common function for Lua Output
 */

#include "suricata-common.h"
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
#include "util-conf.h"

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "action-globals.h"

int LuaCallbackError(lua_State *luastate, const char *msg)
{
    lua_pushnil(luastate);
    lua_pushstring(luastate, msg);
    return 2;
}

const char *LuaGetStringArgument(lua_State *luastate, int idx)
{
    /* get argument */
    if (!lua_isstring(luastate, idx))
        return NULL;
    const char *str = lua_tostring(luastate, idx);
    if (str == NULL)
        return NULL;
    if (strlen(str) == 0)
        return NULL;
    return str;
}

void LuaPushTableKeyValueInt(lua_State *luastate, const char *key, int value)
{
    lua_pushstring(luastate, key);
    lua_pushnumber(luastate, value);
    lua_settable(luastate, -3);
}

/** \brief Push a key plus string value to the stack
 *
 *  If value is NULL, string "(null")" will be put on the stack.
 */
void LuaPushTableKeyValueString(lua_State *luastate, const char *key, const char *value)
{
    lua_pushstring(luastate, key);
    lua_pushstring(luastate, value ? value : "(null)");
    lua_settable(luastate, -3);
}

void LuaPushTableKeyValueArray(lua_State *luastate, const char *key, const uint8_t *value, size_t len)
{
    lua_pushstring(luastate, key);
    LuaPushStringBuffer(luastate, value, len);
    lua_settable(luastate, -3);
}

/** \internal
 *  \brief fill lua stack with payload
 *  \param luastate the lua state
 *  \param p packet
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: payload (string), open (bool), close (bool), toserver (bool), toclient (bool)
 */
static int LuaCallbackStreamingBufferPushToStack(lua_State *luastate, const LuaStreamingBuffer *b)
{
    //PrintRawDataFp(stdout, (uint8_t *)b->data, b->data_len);
    lua_pushlstring (luastate, (const char *)b->data, b->data_len);
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_OPEN));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_CLOSE));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_TOSERVER));
    lua_pushboolean (luastate, (b->flags & OUTPUT_STREAMING_FLAG_TOCLIENT));
    return 5;
}

/** \internal
 *  \brief Wrapper for getting payload into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackStreamingBuffer(lua_State *luastate)
{
    const LuaStreamingBuffer *b = LuaStateGetStreamingBuffer(luastate);
    if (b == NULL)
        return LuaCallbackError(luastate, "internal error: no buffer");

    return LuaCallbackStreamingBufferPushToStack(luastate, b);
}

/** \internal
 *  \brief fill lua stack with signature info
 *  \param luastate the lua state
 *  \param s pointer to signature struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: sid (number), rev (number), gid (number)
 */
static int LuaCallbackRuleIdsPushToStackFromSignature(lua_State *luastate, const Signature *s)
{
    lua_pushinteger(luastate, s->id);
    lua_pushinteger(luastate, s->rev);
    lua_pushinteger(luastate, s->gid);
    return 3;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 *
 *  Info is pulled from PacketAlert if it exists in lua registry (true for logging scripts)
 *  otherwise pulled from Signature in lua registry (for match scripts)
 */
static int LuaCallbackRuleIds(lua_State *luastate)
{
    const Signature *s = NULL;
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa != NULL) {
        s = pa->s;
    } else {
        s = LuaStateGetSignature(luastate);
        if (s == NULL)
            return LuaCallbackError(luastate, "internal error: no packet alert or signature");
    }
    return LuaCallbackRuleIdsPushToStackFromSignature(luastate, s);
}

/** \internal
 *  \brief fill lua stack with signature info
 *  \param luastate the lua state
 *  \param s pointer to signature struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: action (string)
 */
static int LuaCallbackRuleActionPushToStackFromSignature(lua_State *luastate, const Signature *s)
{
    const char *action = "";
    if (s->action & ACTION_PASS) {
        action = "pass";
    } else if ((s->action & ACTION_REJECT) || (s->action & ACTION_REJECT_BOTH) ||
               (s->action & ACTION_REJECT_DST)) {
        action = "reject";
    } else if (s->action & ACTION_DROP) {
        action = "drop";
    } else if (s->action & ACTION_ALERT) {
        action = "alert";
    }
    lua_pushstring(luastate, action);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 *
 *  Info is pulled from PacketAlert if it exists in lua registry (true for logging scripts)
 *  otherwise pulled from Signature in lua registry (for match scripts)
 */
static int LuaCallbackRuleAction(lua_State *luastate)
{
    const Signature *s = NULL;
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa != NULL) {
        s = pa->s;
    } else {
        s = LuaStateGetSignature(luastate);
        if (s == NULL)
            return LuaCallbackError(luastate, "internal error: no packet alert or signature");
    }
    return LuaCallbackRuleActionPushToStackFromSignature(luastate, s);
}

/** \internal
 *  \brief fill lua stack with signature info
 *  \param luastate the lua state
 *  \param s pointer to signature struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: msg (string)
 */
static int LuaCallbackRuleMsgPushToStackFromSignature(lua_State *luastate, const Signature *s)
{
    lua_pushstring(luastate, s->msg);
    return 1;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 *
 *  Info is pulled from PacketAlert if it exists in lua registry (true for logging scripts)
 *  otherwise pulled from Signature in lua registry (for match scripts)
 */
static int LuaCallbackRuleMsg(lua_State *luastate)
{
    const Signature *s = NULL;
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa != NULL) {
        s = pa->s;
    } else {
        s = LuaStateGetSignature(luastate);
        if (s == NULL)
            return LuaCallbackError(luastate, "internal error: no packet alert or signature");
    }
    return LuaCallbackRuleMsgPushToStackFromSignature(luastate, s);
}

/** \internal
 *  \brief fill lua stack with signature info
 *  \param luastate the lua state
 *  \param s pointer to signature struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: class (string), prio (number)
 */
static int LuaCallbackRuleClassPushToStackFromSignature(lua_State *luastate, const Signature *s)
{
    lua_pushstring(luastate, s->class_msg);
    lua_pushinteger(luastate, s->prio);
    return 2;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 *
 *  Info is pulled from PacketAlert if it exists in lua registry (true for logging scripts)
 *  otherwise pulled from Signature in lua registry (for match scripts)
 */
static int LuaCallbackRuleClass(lua_State *luastate)
{
    const Signature *s = NULL;
    const PacketAlert *pa = LuaStateGetPacketAlert(luastate);
    if (pa != NULL) {
        s = pa->s;
    } else {
        s = LuaStateGetSignature(luastate);
        if (s == NULL)
            return LuaCallbackError(luastate, "internal error: no packet alert or signature");
    }
    return LuaCallbackRuleClassPushToStackFromSignature(luastate, s);
}

static int LuaCallbackLogPath(lua_State *luastate)
{
    const char *ld = ConfigGetLogDirectory();
    if (ld == NULL)
        return LuaCallbackError(luastate, "internal error: no log dir");

    return LuaPushStringBuffer(luastate, (const uint8_t *)ld, strlen(ld));
}

static int LuaCallbackLogDebug(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    SCLogDebug("%s", msg);
    return 0;
}

static int LuaCallbackLogInfo(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");

    lua_Debug ar;
    lua_getstack(luastate, 1, &ar);
    lua_getinfo(luastate, "nSl", &ar);
    const char *funcname = ar.name ? ar.name : ar.what;
    SCLogInfoRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    return 0;
}

static int LuaCallbackLogNotice(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");

    lua_Debug ar;
    lua_getstack(luastate, 1, &ar);
    lua_getinfo(luastate, "nSl", &ar);
    const char *funcname = ar.name ? ar.name : ar.what;
    SCLogNoticeRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    return 0;
}

static int LuaCallbackLogWarning(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");

    lua_Debug ar;
    lua_getstack(luastate, 1, &ar);
    lua_getinfo(luastate, "nSl", &ar);
    const char *funcname = ar.name ? ar.name : ar.what;
    SCLogWarningRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    return 0;
}

static int LuaCallbackLogError(lua_State *luastate)
{
    const char *msg = LuaGetStringArgument(luastate, 1);
    if (msg == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");
    lua_Debug ar;
    lua_getstack(luastate, 1, &ar);
    lua_getinfo(luastate, "nSl", &ar);
    const char *funcname = ar.name ? ar.name : ar.what;
    SCLogErrorRaw(ar.short_src, funcname, ar.currentline, "%s", msg);
    return 0;
}

/** \internal
 *  \brief fill lua stack with file info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: fileid (number), txid (number), name (string),
 *          size (number), magic (string), md5 in hex (string),
 *          sha1 (string), sha256 (string)
 */
static int LuaCallbackFileInfoPushToStackFromFile(lua_State *luastate, const File *file)
{
    char *md5ptr = NULL;
    char *sha1ptr = NULL;
    char *sha256ptr = NULL;

    char md5[33] = "";
    md5ptr = md5;
    if (file->flags & FILE_MD5) {
        size_t x;
        for (x = 0; x < sizeof(file->md5); x++) {
            char one[3] = "";
            snprintf(one, sizeof(one), "%02x", file->md5[x]);
            strlcat(md5, one, sizeof(md5));
        }
    }
    char sha1[41] = "";
    sha1ptr = sha1;
    if (file->flags & FILE_SHA1) {
        size_t x;
        for (x = 0; x < sizeof(file->sha1); x++) {
            char one[3] = "";
            snprintf(one, sizeof(one), "%02x", file->sha1[x]);
            strlcat(sha1, one, sizeof(sha1));
        }
    }
    char sha256[65] = "";
    sha256ptr = sha256;
    if (file->flags & FILE_SHA256) {
        size_t x;
        for (x = 0; x < sizeof(file->sha256); x++) {
            char one[3] = "";
            snprintf(one, sizeof(one), "%02x", file->sha256[x]);
            strlcat(sha256, one, sizeof(sha256));
        }
    }

    lua_Integer tx_id = LuaStateGetTxId(luastate);
    lua_pushinteger(luastate, file->file_store_id);
    lua_pushinteger(luastate, tx_id);
    lua_pushlstring(luastate, (char *)file->name, file->name_len);
    lua_pushinteger(luastate, FileTrackedSize(file));
    lua_pushstring (luastate,
#ifdef HAVE_MAGIC
                    file->magic
#else
                    "nomagic"
#endif
                    );
    lua_pushstring(luastate, md5ptr);
    lua_pushstring(luastate, sha1ptr);
    lua_pushstring(luastate, sha256ptr);
    return 8;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackFileInfo(lua_State *luastate)
{
    const File *file = LuaStateGetFile(luastate);
    if (file == NULL)
        return LuaCallbackError(luastate, "internal error: no file");

    return LuaCallbackFileInfoPushToStackFromFile(luastate, file);
}

/** \internal
 *  \brief fill lua stack with file info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: state (string), stored (bool)
 */
static int LuaCallbackFileStatePushToStackFromFile(lua_State *luastate, const File *file)
{
    const char *state = "UNKNOWN";
    switch (file->state) {
        case FILE_STATE_CLOSED:
            state = "CLOSED";
            break;
        case FILE_STATE_TRUNCATED:
            state = "TRUNCATED";
            break;
        case FILE_STATE_ERROR:
            state = "ERROR";
            break;
        case FILE_STATE_OPENED:
            state = "OPENED";
            break;
        case FILE_STATE_NONE:
            state = "NONE";
            break;
        case FILE_STATE_MAX:
            break;
    }

    lua_pushstring (luastate, state);
    lua_pushboolean (luastate, file->flags & FILE_STORED);
    return 2;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackFileState(lua_State *luastate)
{
    const File *file = LuaStateGetFile(luastate);
    if (file == NULL)
        return LuaCallbackError(luastate, "internal error: no file");

    return LuaCallbackFileStatePushToStackFromFile(luastate, file);
}

/** \internal
 *  \brief fill lua stack with thread info
 *  \param luastate the lua state
 *  \param pa pointer to packet alert struct
 *  \retval cnt number of data items placed on the stack
 *
 *  Places: thread id (number), thread name (string, thread group name (string)
 */
static int LuaCallbackThreadInfoPushToStackFromThreadVars(lua_State *luastate, const ThreadVars *tv)
{
    unsigned long tid = SCGetThreadIdLong();
    lua_pushinteger (luastate, (lua_Integer)tid);
    lua_pushstring (luastate, tv->name);
    lua_pushstring (luastate, tv->thread_group_name);
    return 3;
}

/** \internal
 *  \brief Wrapper for getting tuple info into a lua script
 *  \retval cnt number of items placed on the stack
 */
static int LuaCallbackThreadInfo(lua_State *luastate)
{
    const ThreadVars *tv = LuaStateGetThreadVars(luastate);
    if (tv == NULL)
        return LuaCallbackError(luastate, "internal error: no tv");

    return LuaCallbackThreadInfoPushToStackFromThreadVars(luastate, tv);
}

int LuaRegisterFunctions(lua_State *luastate)
{
    /* registration of the callbacks */
    lua_pushcfunction(luastate, LuaCallbackStreamingBuffer);
    lua_setglobal(luastate, "SCStreamingBuffer");

    lua_pushcfunction(luastate, LuaCallbackLogPath);
    lua_setglobal(luastate, "SCLogPath");

    lua_pushcfunction(luastate, LuaCallbackLogDebug);
    lua_setglobal(luastate, "SCLogDebug");
    lua_pushcfunction(luastate, LuaCallbackLogInfo);
    lua_setglobal(luastate, "SCLogInfo");
    lua_pushcfunction(luastate, LuaCallbackLogNotice);
    lua_setglobal(luastate, "SCLogNotice");
    lua_pushcfunction(luastate, LuaCallbackLogWarning);
    lua_setglobal(luastate, "SCLogWarning");
    lua_pushcfunction(luastate, LuaCallbackLogError);
    lua_setglobal(luastate, "SCLogError");


    lua_pushcfunction(luastate, LuaCallbackRuleIds);
    lua_setglobal(luastate, "SCRuleIds");
    lua_pushcfunction(luastate, LuaCallbackRuleAction);
    lua_setglobal(luastate, "SCRuleAction");
    lua_pushcfunction(luastate, LuaCallbackRuleMsg);
    lua_setglobal(luastate, "SCRuleMsg");
    lua_pushcfunction(luastate, LuaCallbackRuleClass);
    lua_setglobal(luastate, "SCRuleClass");

    lua_pushcfunction(luastate, LuaCallbackFileInfo);
    lua_setglobal(luastate, "SCFileInfo");
    lua_pushcfunction(luastate, LuaCallbackFileState);
    lua_setglobal(luastate, "SCFileState");

    lua_pushcfunction(luastate, LuaCallbackThreadInfo);
    lua_setglobal(luastate, "SCThreadInfo");
    return 0;
}

int LuaStateNeedProto(lua_State *luastate, AppProto alproto)
{
    AppProto flow_alproto = 0;
    Flow *flow = LuaStateGetFlow(luastate);
    if (flow == NULL)
        return LuaCallbackError(luastate, "internal error: no flow");

    flow_alproto = flow->alproto;

    return (alproto == flow_alproto);
}
