/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Utility code for dealing with a pidfile.
 * Adaptation of Steve Grubbs patch to our coding guidelines
 * (thanks for the patch Steve ;)
 */

#include "suricata-common.h"
#include "util-pidfile.h"

/**
 * \brief Write a pid file (used at the startup)
 *        This commonly needed by the init scripts
 *
 * \param pointer to the name of the pid file to write (optarg)
 *
 * \retval 0 if succes
 * \retval -1 on failure
 */
int SCPidfileCreate(const char *pidfile)
{
    SCEnter();

    int pidfd = 0;
    char val[16];

    size_t len = snprintf(val, sizeof(val), "%"PRIuMAX"\n", (uintmax_t)getpid());
    if (len <= 0) {
        SCLogError(SC_ERR_PIDFILE_SNPRINTF, "Pid error (%s)", strerror(errno));
        SCReturnInt(-1);
    }

    pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
    if (pidfd < 0) {
        SCLogError(SC_ERR_PIDFILE_OPEN, "unable to set pidfile '%s': %s",
                   pidfile,
                   strerror(errno));
        SCReturnInt(-1);
    }

    ssize_t r = write(pidfd, val, (unsigned int)len);
    if (r == -1) {
        SCLogError(SC_ERR_PIDFILE_WRITE, "unable to write pidfile: %s", strerror(errno));
        close(pidfd);
        SCReturnInt(-1);
    } else if ((size_t)r != len) {
        SCLogError(SC_ERR_PIDFILE_WRITE, "unable to write pidfile: wrote"
                " %"PRIdMAX" of %"PRIuMAX" bytes.", (intmax_t)r, (uintmax_t)len);
        close(pidfd);
        SCReturnInt(-1);
    }

    close(pidfd);
    SCReturnInt(0);
}

/**
 * \brief Remove the pid file (used at the startup)
 *
 * \param pointer to the name of the pid file to write (optarg)
 */
void SCPidfileRemove(const char *pid_filename)
{
    if (pid_filename != NULL) {
        /* we ignore the result, the user may have removed the file already. */
        (void)unlink(pid_filename);
    }
}

/**
 * \brief Check the Suricata pid file (used at the startup)
 *
 * This commonly needed by the init scripts.
 *
 * This function will fail if the PID file exists, but tries to log a
 * meaningful message if appears Suricata is running, or if the PID
 * file appears to be stale.
 *
 * \param pointer to the name of the pid file to write (optarg)
 *
 * \retval 0 if succes
 * \retval -1 on failure
 */
int SCPidfileTestRunning(const char *pid_filename)
{
    if (access(pid_filename, F_OK) == 0) {
        /* Check if the existing process is still alive. */
        FILE *pf;

        // coverity[toctou : FALSE]
        pf = fopen(pid_filename, "r");
        if (pf == NULL) {
            SCLogError(SC_ERR_INITIALIZATION,
                    "pid file '%s' exists and can not be read. Aborting!",
                    pid_filename);
            return -1;
        }

#ifndef OS_WIN32
        pid_t pidv;
        if (fscanf(pf, "%d", &pidv) == 1 && kill(pidv, 0) == 0) {
            SCLogError(SC_ERR_INITIALIZATION,
                    "pid file '%s' exists and Suricata appears to be running. "
                    "Aborting!", pid_filename);
        } else
#endif
        {
            SCLogError(SC_ERR_INITIALIZATION,
                    "pid file '%s' exists but appears stale. "
                    "Make sure Suricata is not running and then remove %s. "
                    "Aborting!",
                    pid_filename, pid_filename);
        }

        fclose(pf);
        return -1;
    }
    return 0;
}
