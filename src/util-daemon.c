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
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 * Daemonization process
 */

#include "suricata.h"
#include "suricata-common.h"
#include "runmodes.h"
#include "util-daemon.h"
#include "util-debug.h"
#include "conf.h"

#ifndef OS_WIN32

#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

static volatile sig_atomic_t sigflag = 0;

/**
 * \brief Signal handler used to take the parent process out of stand-by
 */
static void SignalHandlerSigusr1 (int signo)
{
    sigflag = 1;
}

/**
 * \brief Tell the parent process the child is ready
 *
 * \param pid pid of the parent process to signal
 */
static void TellWaitingParent (pid_t pid)
{
    kill(pid, SIGUSR1);
}

/**
 * \brief Set the parent on stand-by until the child is ready
 *
 * \param pid pid of the child process to wait
 */
static void WaitForChild (pid_t pid)
{
    int status;
    SCLogDebug("Daemon: Parent waiting for child to be ready...");
    /* Wait until child signals is ready */
    while (sigflag == 0) {
        if (waitpid(pid, &status, WNOHANG)) {
            /* Check if the child is still there, otherwise the parent should exit */
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                SCLogError(SC_ERR_DAEMON, "Child died unexpectedly");
                exit(EXIT_FAILURE);
            }
        }
        /* sigsuspend(); */
        sleep(1);
    }
}

/**
 * \brief Close stdin, stdout, stderr.Redirect logging info to syslog
 *
 */
static void SetupLogging (void)
{
    /* Redirect stdin, stdout, stderr to /dev/null  */
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
        return;
    (void)dup2(fd, 0);
    (void)dup2(fd, 1);
    (void)dup2(fd, 2);
    close(fd);
}

/**
 * \brief Daemonize the process
 *
 */
void Daemonize (void)
{
    pid_t pid, sid;

    /* Register the signal handler */
    signal(SIGUSR1, SignalHandlerSigusr1);

    /** \todo We should check if wie allow more than 1 instance
              to run simultaneously. Maybe change the behaviour
              through conf file */

    /* Creates a new process */
    pid = fork();

    if (pid < 0) {
        /* Fork error */
        SCLogError(SC_ERR_DAEMON, "Error forking the process");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        /* Child continues here */
        const char *daemondir;

        umask(027);

        sid = setsid();
        if (sid < 0) {
            SCLogError(SC_ERR_DAEMON, "Error creating new session");
            exit(EXIT_FAILURE);
        }

        if (ConfGet("daemon-directory", &daemondir) == 1) {
            if ((chdir(daemondir)) < 0) {
                SCLogError(SC_ERR_DAEMON, "Error changing to working directory");
                exit(EXIT_FAILURE);
            }
        }
#ifndef OS_WIN32
        else {
            if (chdir("/") < 0) {
                SCLogError(SC_ERR_DAEMON, "Error changing to working directory '/'");
            }
        }
#endif

        SetupLogging();

        /* Child is ready, tell its parent */
        TellWaitingParent(getppid());

        /* Daemon is up and running */
        SCLogDebug("Daemon is running");
        return;
    }
    /* Parent continues here, waiting for child to be ready */
    SCLogDebug("Parent is waiting for child to be ready");
    WaitForChild(pid);

    /* Parent exits */
    SCLogDebug("Child is ready, parent exiting");
    exit(EXIT_SUCCESS);

}

#endif /* ifndef OS_WIN32 */

/**
 * \brief Check for a valid combination daemon/mode
 *
 * \param daemon daemon on or off
 * \param mode selected mode
 *
 * \retval 1 valid combination
 * \retval 0 invalid combination
 */
int CheckValidDaemonModes (int daemon, int mode)
{
    if (daemon) {
        switch (mode) {
            case RUNMODE_PCAP_FILE:
                SCLogError(SC_ERR_INVALID_RUNMODE, "ERROR: pcap offline mode cannot run as daemon");
                return 0;
            case RUNMODE_UNITTEST:
                SCLogError(SC_ERR_INVALID_RUNMODE, "ERROR: unittests cannot run as daemon");
                return 0;
            default:
                SCLogDebug("Allowed mode");
                break;
        }
    }
    return 1;
}
