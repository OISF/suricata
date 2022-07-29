/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "util-signal.h"

int UtilSignalBlock(int signum)
{
#ifndef OS_WIN32
    sigset_t x;
    if (sigemptyset(&x) < 0)
        return -1;
    if (sigaddset(&x, signum) < 0)
        return -1;
    /* don't use sigprocmask(), as it's undefined for
     * multithreaded programs. Use phtread_sigmask().
     */
    if (pthread_sigmask(SIG_BLOCK, &x, NULL) != 0)
        return -1;
#endif
    return 0;
}

int UtilSignalUnblock(int signum)
{
#ifndef OS_WIN32
    sigset_t x;
    if (sigemptyset(&x) < 0)
        return -1;
    if (sigaddset(&x, signum) < 0)
        return -1;
    if (pthread_sigmask(SIG_UNBLOCK, &x, NULL) != 0)
        return -1;
#endif
    return 0;
}

void UtilSignalHandlerSetup(int sig, void (*handler)(int))
{
#ifdef OS_WIN32
	signal(sig, handler);
#else
    struct sigaction action;
    memset(&action, 0x00, sizeof(struct sigaction));

    action.sa_handler = handler;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask),sig);
    action.sa_flags = 0;
    sigaction(sig, &action, 0);
#endif /* OS_WIN32 */

    return;
}

#if 0
int UtilSignalIsHandler(int sig, void (*handler)(int))
{
    struct sigaction action;
    memset(&action, 0x00, sizeof(struct sigaction));

    sigaction(sig, NULL, &action);

    return (action.sa_handler == handler);
}
#endif
