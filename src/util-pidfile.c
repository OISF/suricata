/* Copyright (c) 2010 Open Infomation Security Foundation */

/**
 * \file
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *         Adaptation of Steve Grubbs patch to our conding guidelines
 *         (thanks for the patch Steve ;)
 * \author Victor Julien <victor@inliniac.net>
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
        SCLogError(SC_ERR_PIDFILE_OPEN, "unable to set pidfile: %s", strerror(errno));
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
void SCPidfileRemove(const char *pid_filename) {
    if (pid_filename != NULL) {
        /* we ignore the result, the user may have removed the file already. */
        (void)unlink(pid_filename);
    }
}

