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
#include "util-lua-smtp.h"
#include "util-file.h"

/*
 * \brief internal function used by SMTPGetMimeField
 *
 * \param luastate luastate stack to use and push attributes to
 * \param flow network flow of SMTP packets
 * \param name name of the attribute to extract from MimeDecField
 *
 * \retval 1 if success mimefield found and pushed to stack. Returns error
 * int and msg pushed to luastate stack if error occurs.
 */

static int GetMimeDecField(lua_State *luastate, Flow *flow, const char *name)
{
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
    /* pointer to tail of msg list of MimeDecEntities in current transaction. */
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
    if(field->value == NULL || field->value_len == 0){
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
 * \retval 1 if success mimefield found and pushed to stack. Returns error
 * int and msg pushed to luastate stack if error occurs.
 */

static int SMTPGetMimeField(lua_State *luastate)
{
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "error: protocol not SMTP");
    }
    Flow *flow = LuaStateGetFlow(luastate);
    /* check that flow exist */
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Error: no flow found");
    }
    const char *name = LuaGetStringArgument(luastate, 1);
    if (name == NULL)
        return LuaCallbackError(luastate, "1st argument missing, empty or wrong type");

    GetMimeDecField(luastate, flow, name);

    return 1;
}

/**
 * \brief Internal function used by SMTPGetMimeList
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua
 * \param flow network flow of SMTP packets
 *
 * \retval 1 if the mimelist table is pushed to luastate stack.
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
    if(field->name == NULL || field->name_len == 0) {
        return LuaCallbackError(luastate, "Error: field has no name");
    }
    /* Counter of MIME fields found */
    int num = 1;
    /* loop trough the list of mimeFields, printing each name found */
    lua_newtable(luastate);
    while (field != NULL) {
        if(field->name != NULL && field->name_len != 0) {
            lua_pushinteger(luastate,num++);
            LuaPushStringBuffer(luastate, field->name, field->name_len);
            lua_settable(luastate,-3);
        }
        field = field->next;
    }
    return 1;
}

/**
 * \brief Lists name and value to all MIME fields which
 * is included in a SMTP transaction.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 *
 * \retval 1 if the table is pushed to lua.
 * Returns error int and msg pushed to luastate stack if error occurs
 *
 */

static int SMTPGetMimeList(lua_State *luastate)
{
    /* Check if right protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* Extract network flow */
    Flow *flow = LuaStateGetFlow(luastate);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Error: no flow found");
    }

    GetMimeList(luastate, flow);

    return 1;
}

/**
 * \brief internal function used by SMTPGetMailFrom
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 * \param flow flow to get state for SMTP
 *
 * \retval 1 if mailfrom field found.
 * Retruns error int and msg pushed to luastate stack if error occurs
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
    return LuaPushStringBuffer(luastate, smtp_tx->mail_from, smtp_tx->mail_from_len);
    /* Returns 1 because we never push more then 1 item to the lua stack */
}

/**
 * \brief Extracts mail_from parameter from SMTPState.
 * Attribute may also be available from mimefields, although there is no
 * guarantee of it existing as mime.
 *
 * \param luastate luastate stack to pop and push attributes for I/O to lua.
 *
 * \retval 1 if mailfrom field found.
 * Retruns error int and msg pushed to luastate stack if error occurs
 */

static int SMTPGetMailFrom(lua_State *luastate)
{
    /* check protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* Extract flow, with lockhint to check mutexlocking */
    Flow *flow = LuaStateGetFlow(luastate);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Internal Error: no flow");
    }

    GetMailFrom(luastate, flow);

    return 1;
}

/**
 * \brief intern function used by SMTPGetRcpList
 *
 * \params luastate luastate stack for internal communication with Lua.
 * Used to hand over data to the recieveing luascript.
 *
 * \retval 1 if the table is pushed to lua.
 * Returns error int and msg pushed to luastate stack if error occurs
 */

static int GetRcptList(lua_State *luastate, Flow *flow)
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
        lua_pushinteger(luastate, u++);
        LuaPushStringBuffer(luastate, rcpt->str, rcpt->len);
        lua_settable(luastate, -3);
    }
    /* return 1 since we always push one table to luastate */
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
 * \retval 1 if the table is pushed to lua.
 * Returns error int and msg pushed to luastate stack if error occurs
 */

static int SMTPGetRcptList(lua_State *luastate)
{
    /* check protocol */
    if(!(LuaStateNeedProto(luastate, ALPROTO_SMTP))) {
        return LuaCallbackError(luastate, "Error: protocol not SMTP");
    }
    /* Extract flow, with lockhint to check mutexlocking */
    Flow *flow = LuaStateGetFlow(luastate);
    if(flow == NULL) {
        return LuaCallbackError(luastate, "Internal error: no flow");
    }

    GetRcptList(luastate, flow);

    /* return 1 since we always push one table to luastate */
    return 1;
}

int LuaRegisterSmtpFunctions(lua_State *luastate)
{

    lua_pushcfunction(luastate, SMTPGetMimeField);
    lua_setglobal(luastate, "SMTPGetMimeField");

    lua_pushcfunction(luastate, SMTPGetMimeList);
    lua_setglobal(luastate, "SMTPGetMimeList");

    lua_pushcfunction(luastate, SMTPGetMailFrom);
    lua_setglobal(luastate, "SMTPGetMailFrom");

    lua_pushcfunction(luastate, SMTPGetRcptList);
    lua_setglobal(luastate, "SMTPGetRcptList");

    return 0;
}

#endif /* HAVE_LUA */
