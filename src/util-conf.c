/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 */

#include "suricata-common.h"
#include "config.h"
#include "conf.h"
#include "runmodes.h"
#include "util-conf.h"

#ifndef OS_WIN32

#include "util-privs.h"

extern SCInstance suricata;

#endif /* OS_WIN32 */

TmEcode ConfigSetLogDirectory(char *name)
{
    return ConfSetFinal("default-log-dir", name) ? TM_ECODE_OK : TM_ECODE_FAILED;
}

const char *ConfigGetLogDirectory()
{
    const char *log_dir = NULL;

    if (ConfGet("default-log-dir", &log_dir) != 1) {
#ifdef OS_WIN32
        log_dir = _getcwd(NULL, 0);
        if (log_dir == NULL) {
            log_dir = DEFAULT_LOG_DIR;
        }
#else
        log_dir = DEFAULT_LOG_DIR;
#endif /* OS_WIN32 */
    }

    return log_dir;
}

TmEcode ConfigCheckFileExists(const char *filename)
{
    SCEnter();
#ifdef OS_WIN32
    struct _stat buf;
    if (_stat(log_dir, &buf) != 0) {
#else
    struct stat buf;
    if (stat(filename, &buf) != 0) {
#endif /* OS_WIN32 */
            SCReturnInt(TM_ECODE_FAILED);
    }
    SCReturnInt(TM_ECODE_OK);
}

#ifndef OS_WIN32
/**
 * \brief   Check if requested file is writable after privilege drop.
 *          (Or now if we won't drop privs)
 *
 * \param   filename        Name of file to check
 * \param   suricata    	Pointer to suricata instance, necesarry for priv drop details
 *
 * \retval  TmEcode. TM_ECODE_DONE if writable. TM_ECODE_FAILED otherwise. Never TM_ECODE_OK
 */
TmEcode ConfigCheckFileWritablePrivDrop(const char * const filename)
{
    struct stat file_stat_struct;

    if (stat(filename, &file_stat_struct) != 0) {
        FatalError(SC_ERR_FATAL, "Checking writeability of logfile dir failed with following error message: %s",
                   strerror(errno));
    }

    if (suricata.do_setgid || suricata.do_setuid) { /* We will drop privs */

        if (SCCheckArbitraryFileAccess((uid_t)     suricata.userid,      /* future uid */
                                       (gid_t *) &(suricata.groupid),  /* future gid */
                                       1, /* only one future gid because alle supplementary
                                           * gids will be purged while dropping privs  */
                                       &file_stat_struct,
                                       W_OK /* check for write access */ )) {
            return TM_ECODE_DONE; /* log dir will stay writable */
        }
        return TM_ECODE_FAILED; /* Dir not writeable */

    } else { /* We will stay the user and group(s) we are */
        /* Step 1: getting and preparing data */
        int supplementary_gid_count;

        /* With 0 as first arg getgroups returns the number of existing supplementary gids */
        if ( -1 == (supplementary_gid_count = getgroups(0 , NULL)) ) {
            FatalError(SC_ERR_FATAL, "Getting group IDs of suricata process failed with following error message: %s",
                       strerror(errno));
        }

        /* +1 is for the primary group id we will add later */
        gid_t gids[supplementary_gid_count+1];

        /* get supplementary gids */
        if (supplementary_gid_count != getgroups(supplementary_gid_count, gids)) {
            FatalError(SC_ERR_FATAL, "Getting group IDs of suricata process failed with following error message: %s",
                       strerror(errno));
        }

        /* It's undefinded whether getgroups() also returns our primary gid
         * or only the supplementary gids. So to be safe here we manually
         * add our primary group id to the last slot of the array.
         * If it's already in there this does not break correctness,
         * because the following SCCheckArbitrartyFileAcees()
         * then simply does the check for this gid twice. */
        gids[supplementary_gid_count] = getegid();

        /* Step 2: Calling the low level permission bit check function */
        if (SCCheckArbitraryFileAccess(getuid(), gids, supplementary_gid_count+1,
                                       &file_stat_struct, W_OK)) {
            return TM_ECODE_DONE;
        }
        return TM_ECODE_FAILED;
    }
}
#endif /* OS_WIN32 */

/**
 * \brief Find the configuration node for a specific device.

 * Basically hunts through the list of maps for the first one with a
 * key of "interface", and a value of the provided interface.
 *
 * \param node The node to start looking for the device
 *     configuration. Typically this would be something like the af-packet
 *     or pf-ring node.
 *
 * \param iface The name of the interface to find the config for.
 */
ConfNode *ConfFindDeviceConfig(ConfNode *node, const char *iface)
{
    ConfNode *if_node, *item;
    TAILQ_FOREACH(if_node, &node->head, next) {
        TAILQ_FOREACH(item, &if_node->head, next) {
            if (strcmp(item->name, "interface") == 0 &&
                strcmp(item->val, iface) == 0) {
                return if_node;
            }
        }
    }

    return NULL;
}

int ConfUnixSocketIsEnable(void)
{
    const char *value;

    if (ConfGet("unix-command.enabled", &value) != 1) {
        return 0;
    }

    if (value == NULL) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "malformed value for unix-command.enabled: NULL");
        return 0;
    }

    if (!strcmp(value, "auto")) {
#ifdef HAVE_LIBJANSSON
#ifdef OS_WIN32
        return 0;
#else
        if (!IsRunModeOffline(RunmodeGetCurrent())) {
            SCLogInfo("Running in live mode, activating unix socket");
            return 1;
        } else {
            return 0;
        }
#endif
#else
        return 0;
#endif
    }

    return ConfValIsTrue(value);
}
