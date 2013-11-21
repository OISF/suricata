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

TmEcode ConfigSetLogDirectory(char *name)
{
    return ConfSetFinal("default-log-dir", name) ? TM_ECODE_OK : TM_ECODE_FAILED;
}

char *ConfigGetLogDirectory()
{
    char *log_dir = NULL;

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

TmEcode ConfigCheckLogDirectory(char *log_dir)
{
    SCEnter();
#ifdef OS_WIN32
    struct _stat buf;
    if (_stat(log_dir, &buf) != 0) {
#else
    struct stat buf;
    if (stat(log_dir, &buf) != 0) {
#endif /* OS_WIN32 */
            SCReturnInt(TM_ECODE_FAILED);
    }
    SCReturnInt(TM_ECODE_OK);
}
