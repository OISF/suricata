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
#include "suricata.h"
#include "conf.h"
#include "runmodes.h"
#include "util-conf.h"
#include "util-debug.h"
#include "util-path.h"

TmEcode ConfigSetLogDirectory(const char *name)
{
    return SCConfSetFinal("default-log-dir", name) ? TM_ECODE_OK : TM_ECODE_FAILED;
}

const char *SCConfigGetLogDirectory(void)
{
    const char *log_dir = NULL;

    if (SCConfGet("default-log-dir", &log_dir) != 1) {
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

TmEcode ConfigCheckLogDirectoryExists(const char *log_dir)
{
    SCEnter();
    SCStat buf;
    if (SCStatFn(log_dir, &buf) != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCReturnInt(TM_ECODE_OK);
}

TmEcode ConfigSetDataDirectory(char *name)
{
    if (strlen(name) == 0)
        return TM_ECODE_OK;

    size_t size = strlen(name) + 1;
    char tmp[size];
    strlcpy(tmp, name, size);
    if (size > 2 && tmp[size - 2] == '/') // > 2 to allow just /
        tmp[size - 2] = '\0';

    return SCConfSetFinal("default-data-dir", tmp) ? TM_ECODE_OK : TM_ECODE_FAILED;
}

const char *ConfigGetDataDirectory(void)
{
    const char *data_dir = NULL;

    if (SCConfGet("default-data-dir", &data_dir) != 1) {
#ifdef OS_WIN32
        data_dir = _getcwd(NULL, 0);
        if (data_dir == NULL) {
            data_dir = DEFAULT_DATA_DIR;
        }
#else
        data_dir = DEFAULT_DATA_DIR;
#endif /* OS_WIN32 */
    }

    SCLogDebug("returning '%s'", data_dir);
    return data_dir;
}

TmEcode ConfigCheckDataDirectory(const char *data_dir)
{
    SCEnter();
    SCStat buf;
    if (SCStatFn(data_dir, &buf) != 0) {
        SCReturnInt(TM_ECODE_FAILED);
    }
    SCReturnInt(TM_ECODE_OK);
}

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
SCConfNode *ConfFindDeviceConfig(SCConfNode *node, const char *iface)
{
    SCConfNode *if_node, *item;
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

    if (SCConfGet("unix-command.enabled", &value) != 1) {
        return 0;
    }

    if (value == NULL) {
        SCLogError("malformed value for unix-command.enabled: NULL");
        return 0;
    }

    if (!strcmp(value, "auto")) {
#ifdef OS_WIN32
        return 0;
#else
        if (!IsRunModeOffline(SCRunmodeGet())) {
            SCLogInfo("Running in live mode, activating unix socket");
            return 1;
        } else {
            return 0;
        }
#endif
    }

    return SCConfValIsTrue(value);
}
