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
 *  \file
 *
 *  \author casec Bachelors group
 *  \author Lauritz Prag Sømme <lauritz24@me.com>
 *  \author Levi Tobiassen <levi.tobiassen@gmail.com>
 *  \author Stian Hoel Bergseth <stian.bergseth@hig.no>
 *  \author Vinjar Hillestad <vinjar.hillestad@hig.no>
 */

#include "suricata-common.h"

#include "debug.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "output.h"

#include "app-layer-smtp.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>

#include "util-lua.h"
#include "util-lua-common.h"
#include "util-file.h"

/*
 * \brief Function extracts MimeDecField from
 * flow->SMTPState->SMTPTransaction->MimeDecEntity->MimeDecField
 * based on parameter name, set in previous, spesified function.
 *
 * \param luastate luastate stack to use and push attributes to
 * \param flow network flow of SMTP packets
 * \param name name of the attribute to extract from MimeDecField
 *
 * \retval returns number of attributes pushed to luastate stack,
 * or error int + error msg to stack
 */

static int GetMimeDecField(lua_State *luastate, Flow *flow, const char *name) {
    /* extract state from flow */
    SMTPState *state = (SMTPState *) FlowGetAppState(flow);
    /* check that state exsists */
    if(state == NULL) {
        return LuaCallbackError(luastate, "Internal error: no state in flow");
    }
    /* pointer to current transaction in state */
    SMTPTransaction *smtp_tx = state->curr_tx;
    if(smtp_tx == NULL) {
        return LuaCallbackError(luastate, "Transaction ending or not found");
    }
    /* pointer to tail of msg list of MimeDecEntitys in current transaction. */
    MimeDecEntity *mime = smtp_tx->msg_tail;
    /* check if msg_tail was hit */
    if(mime == NULL){
        return LuaCallbackError(luastate, "Internal error: no fields in transaction");
    }
    /* extract MIME field based on spesific field name. */
    MimeDecField *field = MimeDecFindField(mime, name);
    /* check MIME field */
    if(field == NULL) {
        return LuaCallbackError(luastate, "Error: mimefield not found");
    }
    /* return extracted field. */
    if(!(strlen((const char*) field->value) == field->value_len)){
        return LuaCallbackError(luastate, "Error, pointer error");
    }

    return LuaPushStringBuffer(luastate, field->value, field->value_len);
}

/**
 * \brief Function extracts specific MIME field based on argument from luastate
 * stack then pushing the attribute onto the luastate stack.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua
 *
 * \retval int 1 if success mimefield found and pushed to stack. Returns error
 * int and msg pushed to luastate stack if error occurs.
 */

static int SMTPGetMimeField(lua_State *luastate)
{
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "error: protocol not SMTP");
    }
    int lock_hint = 0;
    Flow *flow = LuaStateGetFlow(luastate, &lock_hint);
    /* check that flow exist */
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Error: no flow found");
    }
    const char *name = LuaGetStringArgument(luastate, 1);
    /* lock check */
    if(lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        FLOWLOCK_RDLOCK(flow);
        /* get specific MIME field */
        int subject_res = GetMimeDecField(luastate, flow, name);
        /* unlock flow mutex to allow for multithreading */
        FLOWLOCK_UNLOCK(flow);
        /* return number of fields pushed to luastate */
        return subject_res;
    } else { /* if mutex already locked */
        return GetMimeDecField(luastate, flow, name);
    }
}


/**
 * \brief creates a list of all MIME fields found in an SMTP transaction
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua
 * \param flow network flow of SMTP packets
 *
 * \retval int 1 if success mimefield found and pushed to stack.
 * Returns error int and msg pushed to luastate stack if error occurs.
*/

static int GetMimeList(lua_State *luastate, Flow *flow)
{

    SMTPState *state = (SMTPState *) FlowGetAppState(flow);
    if(state == NULL) {
        return LuaCallbackError(luastate, "Error: no SMTP state");
    }
    /* Create a pointer to the current SMTPtransaction */
    SMTPTransaction *smtp_tx = state->curr_tx;
    if(smtp_tx == NULL) {
        return LuaCallbackError(luastate, "Error: no SMTP transaction found");
    }
    /* Create a pointer to the tail of MimeDecEntity list */
    MimeDecEntity *mime = smtp_tx->msg_tail;
    if(mime == NULL) {
        return LuaCallbackError(luastate, "Error: no mime entity found");
    }
    MimeDecField *field = mime->field_list;
    if(field == NULL) {
        return LuaCallbackError(luastate, "Error: no field_list found");
    }
    /* Counter of MIME fields found */
    int num = 1;
    /* loop trough the list of mimeFields, printing each name found */
    lua_newtable(luastate);
    while (field != NULL) {
        if(field->name != NULL) {
            lua_pushinteger(luastate,num++);
            LuaPushStringBuffer(luastate, field->name, field->name_len);
            lua_settable(luastate,-3);
        }
        field = field->next;
    }
    return 1;
}

/**
 * \brief function for dedicated for dev-use. Lists name and value to all MIME
 * fields which is included in the a SMTP transaction.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 *
 * \retval int 1 if the table is pushed to lua.
 * Returns error int and msg pushed to luastate stack if error occurs
 *
 */

static int SMTPGetMimeList(lua_State *luastate)
{
    /* Check if right protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* mutex lock indicator var */
    int lock_hint = 0;
    /* Extract network flow */
    Flow *flow = LuaStateGetFlow(luastate, &lock_hint);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Error: no flow found");
    }
    int retval;
    /* check if flow already locked */
    if(lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        /* mutexlock flow */
        FLOWLOCK_RDLOCK(flow);
        retval = GetMimeList(luastate, flow);
        FLOWLOCK_UNLOCK(flow);
    } else {
        retval = GetMimeList(luastate, flow);
    }
    return retval;
}

/**
 * \brief Extracts mail_from parameter from SMTPState.
 * Attribute may also be available from MIME fields, although
 * there is no guarantee of it existing as MIME.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 * \param flow flow to get state for SMTP
 *
 * \retval returns number of attributes pushed to luastate stack.
 */

static int GetMailFrom(lua_State *luastate, Flow *flow)
{
    /* Extract SMTPstate from current flow */
    SMTPState *state = (SMTPState *) FlowGetAppState(flow);

    if(state == NULL) {
        return LuaCallbackError(luastate, "Internal Error: no state");
    }
    SMTPTransaction *smtp_tx = state->curr_tx;
    if(smtp_tx == NULL) {
        return LuaCallbackError(luastate, "Internal Error: no SMTP transaction");
    }
    if(smtp_tx->mail_from == NULL || smtp_tx->mail_from_len == 0) {
        return LuaCallbackError(luastate, "MailFrom not found");
    }
    LuaPushStringBuffer(luastate, smtp_tx->mail_from, smtp_tx->mail_from_len);
    /* Returns 1 because we never push more then 1 item to the lua stack */
    return 1;
}

/**
 * \brief Extracts mail_from parameter from SMTPState.
 * Attribute may also be available from mimefields, although there is no
 * guarantee of it existing as mime.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 *
 * \retval returns number of attributes pushed to luastate stack.
 */

static int SMTPGetMailFrom(lua_State *luastate)
{
    /* check protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* use lock_hint to check for mutexlock on flow */
    int lock_hint = 0;
    /* Extract flow, with lockhint to check mutexlocking */
    Flow *flow = LuaStateGetFlow(luastate, &lock_hint);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Internal Error: no flow");
    }
    int retval;
    /* check if already mutexlocked by parents */
    if(lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        /* mutexlock flow */
        FLOWLOCK_RDLOCK(flow);
        retval = GetMailFrom(luastate, flow);
        FLOWLOCK_UNLOCK(flow);
    } else {
        retval = GetMailFrom(luastate, flow);
    }
    return retval;
}

/**
 * \brief function loops through rcpt-list located in
 * flow->SMTPState->SMTPTransaction, adding all items to a table.
 * Then pushing it to the luastate stack.
 *
 * \params luastate luastate stack for internal communication with Lua.
 * Used to hand over data to the recieveing luascript.
 *
 * \retval 1 or error - number of attibutes pushed to the luastate stack.
 */

static int GetrcptList(lua_State *luastate, Flow *flow)
{

    SMTPState *state = (SMTPState *) FlowGetAppState(flow);
    if(state == NULL) {
        return LuaCallbackError(luastate, "Internal error, no state");
    }

    SMTPTransaction *smtp_tx = state->curr_tx;
    if(smtp_tx == NULL) {
        return LuaCallbackError(luastate, "No more tx, or tx not found");
    }

    /* Create a new table in luastate for rcpt list */
    lua_newtable(luastate);
    /* rcpt var for iterator */
    int u = 1;
    SMTPString *rcpt;

    TAILQ_FOREACH(rcpt, &smtp_tx->rcpt_to_list, next) {
        LuaPushStringBuffer(luastate, rcpt->str, rcpt->len);
        lua_pushinteger(luastate, u++);
        lua_settable(luastate, -3);
    }
    /* Returns 1 because we never push more then 1 item to the lua stack */
    return 1;
}

/**
 * \brief function loops through rcpt-list located in
 * flow->SMTPState->SMTPTransaction, adding all items to a table.
 * Then pushing it to the luastate stack.
 *
 * \params luastate luastate stack for internal communication with Lua.
 * Used to hand over data to the recieveing luascript.
 *
 * \retval 1 or error - number of attibutes pushed to the luastate stack.
 */

static int SMTPGetrcptList(lua_State *luastate)
{
    /* check protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* create lockhint var for flowlock check. */
    int lock_hint = 0;
    /* Extract flow, with lockhint to check mutexlocking */
    Flow *flow = LuaStateGetFlow(luastate, &lock_hint);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Internal error: no flow");
    }
    int retval;
    /* check if already mutexlocked by parents */
    if(lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        /* lock flow */
        FLOWLOCK_RDLOCK(flow);
        retval = GetrcptList(luastate, flow);
        /* open flow */
        FLOWLOCK_UNLOCK(flow);
    } else {
        retval = GetrcptList(luastate, flow);
    }
    return retval;
}

static int GetAttachmentInfo(lua_State *luastate, Flow *flow)
{
    /* Extract SMTPState from flow */
    SMTPState *state = (SMTPState *) FlowGetAppState(flow);
    if(state == NULL) {
        return LuaCallbackError(luastate, "error: state not found");
    }
    /* get FileContainer in SMTPState */
    FileContainer *file_con = state->files_ts;
    if(file_con == NULL) {
        return LuaCallbackError(luastate, "error: no files found");
    }
    /* point to start of list for iterating trough */
    File *file = file_con->head;
    if(file == NULL) {
        return LuaCallbackError(luastate, "error: no file(s) in container");
    }
    int u = 1;
    /* create new table for placement of findings */
    lua_newtable(luastate);
    /* loop through and push filename to luastate table on stack */
    while(file != NULL) {
        lua_pushinteger(luastate, u++);
        lua_newtable(luastate);
        lua_pushstring(luastate, "filename");
        LuaPushStringBuffer(luastate, file->name, file->name_len);
        lua_settable(luastate, -3);
        /* creating for loop temp vars */
#ifdef HAVE_NSS
        char smd5[256];
        int i;
        size_t x;
        /* loops through md5 int array, ports it to char*/
        for (i = 0, x = 0; x < sizeof(file->md5); x++) {
            i += snprintf(&smd5[i], 255-i, "%02x", file->md5[x]);
        }
        /* push md5 char array to luastate stack */
        lua_pushstring(luastate, "md5-field");
        lua_pushstring(luastate, smd5);
        lua_settable(luastate, -3);
        /* set self to next in list */
#endif
        lua_settable(luastate, -3);
        file = file->next;
    }
    return 1;
}

/**
 * \brief Function grabs possible list of file-structs residing inside
 * flow->SMTPState->FileContainer then loops trough this list, pushing a table for
 * each entity, containing the filename and MD5 checksum.
 *
 * \params luastate, luastate for internal communication towards the
 * luascripting engine.
 *
 * \retval Number of attributes pushed to luastate stack, in this case number
 * of tables pushed, and two if an error was found.
 */

static int SMTPGetAttachmentInfo(lua_State *luastate)
{
    /* check protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* create lockhint var for flowlock check.
     * rcpt var for iterator */
    int lock_hint = 0;
    /* Extract flow with luastate */
    Flow *flow = LuaStateGetFlow(luastate, &lock_hint);
    if (flow == NULL) {
        return LuaCallbackError(luastate, "internal error: no flow");
    }
    /* check if flow already mutexlocked */
    int retval;
    if(lock_hint == LUA_FLOW_NOT_LOCKED_BY_PARENT) {
        /* mutexlock flow */
        FLOWLOCK_RDLOCK(flow);
        retval = GetAttachmentInfo(luastate, flow);
        FLOWLOCK_UNLOCK(flow);
    } else {
        retval = GetAttachmentInfo(luastate, flow);
    }
    return retval;
}

int LuaRegisterSmtpFunctions(lua_State *luastate)
{
    lua_pushcfunction(luastate, SMTPGetMailFrom);
    lua_setglobal(luastate, "SMTPGetMailFrom");

    lua_pushcfunction(luastate, SMTPGetrcptList);
    lua_setglobal(luastate, "SMTPGetrcptList");

    lua_pushcfunction(luastate, SMTPGetMimeList);
    lua_setglobal(luastate, "SMTPGetMimeList");

    lua_pushcfunction(luastate, SMTPGetMimeField);
    lua_setglobal(luastate, "SMTPGetMimeField");

    lua_pushcfunction(luastate, SMTPGetAttachmentInfo);
    lua_setglobal(luastate, "SMTPGetAttachmentInfo");

    /* all functions that needs be reachable from lua have to be pushed and
     * set globally here.
     * ex:
     * lua_pushcfunction(luastate, SmtpGetSmptpState);
     * lua_setglobal(luastate, "SmtpGetSmtpState");
     */
    return 0;
}

#endif /* HAVE_LUA */
