/* Copyright (c) 2010 Open Infomation Security Foundation */

/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *         Adaptation of Steve Grubbs patch to our conding guidelines
 *         (thanks for the patch Steve ;)
 */

#include "suricata-common.h"
#include "util-pidfile.h"

/**
 * \brief Write a pid file (used at the startup)
 *        This commonly needed by the init scripts
 * \param pointer to the name of the pid file to write (optarg)
 * \retval 0 if succes; -1 on failure
 */
int SCPidfileCreate(const char *pidfile)
{
    SCEnter();
    int pidfd, len;
    char val[16];

    len = snprintf(val, sizeof(val), "%u\n", getpid());
    if (len <= 0) {
        SCLogError(SC_ERR_PIDLOG, "Pid error (%s)", strerror(errno));
        SCReturnInt(-1);
    }
    pidfd = open(pidfile, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
    if (pidfd < 0) {
        SCLogError(SC_ERR_PIDLOG, "Unable to set pidfile (%s)", strerror(errno));
        SCReturnInt(-1);
    }
    write(pidfd, val, (unsigned int)len);
    close(pidfd);
    SCReturnInt(0);
}

/**
 * \brief Remove the pid file (used at the startup)
 * \param pointer to the name of the pid file to write (optarg)
 */
void SCPidfileRemove(const char *pid_filename) {
    if (pid_filename != NULL)
        unlink(pid_filename);
}
