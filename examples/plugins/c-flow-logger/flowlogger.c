/* Copyright (C) 2023 Open Information Security Foundation
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

#include <stdio.h>
#include <stdlib.h>

#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"

// For PrintInet
#include "util-print.h"

#include "output-flow.h"

static TmEcode ThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    return TM_ECODE_OK;
}

static TmEcode ThreadDeinit(ThreadVars *tv, void *data)
{
    // Nothing to do. If we allocated data in ThreadInit we would free
    // it here.
}

static int FlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    char src_ip[46] = { 0 }, dst_ip[46] = { 0 };
    Port sp, dp;

    if ((f->flags & FLOW_DIR_REVERSED) == 0) {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), src_ip, sizeof(src_ip));
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dst_ip, sizeof(dst_ip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->src.address), src_ip, sizeof(src_ip));
            PrintInet(AF_INET6, (const void *)&(f->dst.address), dst_ip, sizeof(dst_ip));
        }
        sp = f->sp;
        dp = f->dp;
    } else {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), src_ip, sizeof(src_ip));
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), dst_ip, sizeof(dst_ip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->dst.address), src_ip, sizeof(src_ip));
            PrintInet(AF_INET6, (const void *)&(f->src.address), dst_ip, sizeof(dst_ip));
        }
        sp = f->dp;
        dp = f->sp;
    }

    SCLogNotice("Flow: %s:%u -> %s:%u", src_ip, sp, dst_ip, dp);

    return 0;
}

static void Init(void)
{
    OutputRegisterFlowLogger("custom-flow-logger", FlowLogger, NULL, ThreadInit, ThreadDeinit);
}

const SCPlugin PluginRegistration = {
    .name = "FlowLogger",
    .author = "Jason Ish",
    .license = "GPLv2",
    .Init = Init,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
