/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */
#define _POSIX_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <rte_eal.h>

#include "prefilter.h"
#include "logger.h"
#include "lcores-manager.h"
#include "util-prefilter.h"

static volatile int g_should_stop = 0;

void StopWorkers(void)
{
    g_should_stop = 1;
}

static void IPCActionShutdown(void)
{
    int retval;
    struct rte_mp_msg req;
    struct rte_mp_reply reply;
    memset(&req, 0, sizeof(req));
    strlcpy(req.name, IPC_ACTION_SHUTDOWN, sizeof(req.name) / sizeof(req.name[0]));
    req.len_param = 0;
    const struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
    retval = rte_mp_request_sync(&req, &reply, &ts);
    if (retval != 0) {
        Log().error(EFAULT, "Shutdown req-response failed (%s)", rte_strerror(rte_errno));
        // todo: in timeout, PF should continue in shutdown
        exit(1);
    }

    if (reply.nb_sent != reply.nb_received) {
        Log().warning(ETIMEDOUT, "Shutdown req-response timed out for %d of %d apps", reply.nb_received, reply.nb_sent);
    }
}

static void SignalStop(int sig)
{
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            StopWorkers();
            IPCActionShutdown();
            break;
        default:
            break;
    }
}

static void SignalBrokenPmd(int sig)
{
    int ret;
#define HINT "segfault, try --no-pci or start as root\n"

    if (sig != SIGSEGV)
        return;

    ret = (int)write(STDERR_FILENO, HINT, sizeof(HINT) - 1);
    if (ret <= 0)
        fprintf(stderr, "write function failed: %s\n", strerror(errno));
    signal(sig, SIG_DFL);
    kill(getpid(), sig);
}

int ShouldStop(void)
{
    return g_should_stop;
}

void SignalInit(void)
{
    signal(SIGSEGV, &SignalBrokenPmd);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGINT, &SignalStop);
    signal(SIGTERM, &SignalStop);
}