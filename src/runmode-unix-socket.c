/* Copyright (C) 2012 Open Information Security Foundation
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

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-pcap-file.h"
#include "log-httplog.h"
#include "output.h"
#include "cuda-packet-batcher.h"
#include "source-pfring.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "unix-manager.h"

static const char *default_mode = NULL;

int unix_socket_mode_is_running = 0;

const char *RunModeUnixSocketGetDefaultMode(void)
{
    return default_mode;
}

void RunModeUnixSocketRegister(void)
{
#ifdef HAVE_LIBJANSSON
    RunModeRegisterNewRunMode(RUNMODE_UNIX_SOCKET, "single",
                              "Unix socket mode",
                              RunModeUnixSocketSingle);
    default_mode = "single";
#endif
    return;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeUnixSocketSingle(DetectEngineCtx *de_ctx)
{
#ifdef HAVE_LIBJANSSON
    UnixManagerThreadSpawn(de_ctx);

    unix_socket_mode_is_running = 1;
#endif

    return 0;
}

int RunModeUnixSocketIsActive(void)
{
    return unix_socket_mode_is_running;
}
