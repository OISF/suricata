/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifdef HAVE_LUAJIT
#include "conf.h"
#include "util-pool.h"
#include "util-lua.h"
#include "util-luajit.h"

/** \brief lua_State pool
 *
 *  Lua requires states to be alloc'd in memory <2GB. For this reason we
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
static int luajit_states_cnt = 0;
static int luajit_states_cnt_max = 0;
static int luajit_states_size = 0;
#define LUAJIT_DEFAULT_STATES 128

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
int LuajitSetupStatesPool(void)
{
    int retval = 0;
    pthread_mutex_lock(&luajit_states_lock);

    if (luajit_states == NULL) {
        intmax_t cnt = 0;
        if (ConfGetInt("luajit.states", &cnt) != 1) {
            ConfNode *denode = NULL;
            ConfNode *decnf = ConfGetNode("detect-engine");
            if (decnf != NULL) {
                TAILQ_FOREACH(denode, &decnf->head, next) {
                    if (denode->val && strcmp(denode->val, "luajit-states") == 0) {
                        ConfGetChildValueInt(denode, "luajit-states", &cnt);
                    }
                }
            }
        }
        if (cnt == 0) {
            cnt = LUAJIT_DEFAULT_STATES;
        }
        luajit_states_size = cnt;

        luajit_states = PoolInit(0, cnt, 0, LuaStatePoolAlloc, NULL, NULL, NULL, LuaStatePoolFree);
        if (luajit_states == NULL) {
            SCLogError(SC_ERR_LUA_ERROR, "luastate pool init failed, lua/luajit keywords won't work");
            retval = -1;
        }

        if (retval == 0) {
            SCLogConfig("luajit states preallocated: %d", luajit_states_size);
        }
    }

    pthread_mutex_unlock(&luajit_states_lock);
    return retval;
}

void LuajitFreeStatesPool(void)
{
    pthread_mutex_lock(&luajit_states_lock);
    if (luajit_states_cnt_max > luajit_states_size) {
        SCLogNotice("luajit states used %d is bigger than pool size %d. Set "
                "luajit.states to %d to avoid memory issues. "
                "See #1577 and #1955.", luajit_states_cnt_max, luajit_states_size,
                luajit_states_cnt_max);
    }
    PoolFree(luajit_states);
    luajit_states = NULL;
    luajit_states_size = 0;
    luajit_states_cnt = 0;
    pthread_mutex_unlock(&luajit_states_lock);
}

lua_State *LuajitGetState(void)
{
    lua_State *s = NULL;
    pthread_mutex_lock(&luajit_states_lock);
    if (luajit_states != NULL) {
        s = (lua_State *)PoolGet(luajit_states);
        if (s != NULL) {
            if (luajit_states_cnt == luajit_states_size) {
                SCLogWarning(SC_WARN_LUA_SCRIPT, "luajit states pool size %d "
                        "reached. Increase luajit.states config option. "
                        "See #1577 and #1955", luajit_states_size);
            }

            luajit_states_cnt++;
            if (luajit_states_cnt > luajit_states_cnt_max)
                luajit_states_cnt_max = luajit_states_cnt;
        }
    }
    pthread_mutex_unlock(&luajit_states_lock);
    return s;
}

void LuajitReturnState(lua_State *s)
{
    if (s != NULL) {
        pthread_mutex_lock(&luajit_states_lock);
        PoolReturn(luajit_states, (void *)s);
        BUG_ON(luajit_states_cnt <= 0);
        luajit_states_cnt--;
        pthread_mutex_unlock(&luajit_states_lock);
    }
}

#endif /* HAVE_LUAJIT */
