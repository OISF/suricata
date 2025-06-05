/* Copyright (C) 2023-2024 Open Information Security Foundation
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
#include "suricata-plugin.h"

#include "output-packet.h"
#include "output-flow.h"
#include "output-tx.h"
#include "util-print.h"
#include "output.h"

static int CustomPacketLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    char src_ip[46] = { 0 }, dst_ip[46] = { 0 };

    if (PacketIsIPv4(p)) {
        PrintInet(AF_INET, (const void *)&(p->src.addr_data32[0]), src_ip, sizeof(src_ip));
        PrintInet(AF_INET, (const void *)&(p->dst.addr_data32[0]), dst_ip, sizeof(dst_ip));
    } else if (PacketIsIPv6(p)) {
        PrintInet(AF_INET6, (const void *)&(p->src.address), src_ip, sizeof(src_ip));
        PrintInet(AF_INET6, (const void *)&(p->dst.address), dst_ip, sizeof(dst_ip));
    } else {
        SCLogNotice("Packet is not IP");
        return 0;
    }
    SCLogNotice("Packet: %s -> %s", src_ip, dst_ip);
    return 0;
}

static bool CustomPacketLoggerCondition(ThreadVars *tv, void *thread_data, const Packet *)
{
    /* Always true for this example. */
    return true;
}

static int CustomFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
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

static int CustomDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    SCLogNotice("We have a DNS transaction");
    return 0;
}

static TmEcode ThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    return TM_ECODE_OK;
}

static TmEcode ThreadDeinit(ThreadVars *tv, void *data)
{
    // Nothing to do. If we allocated data in ThreadInit we would free
    // it here.
    return TM_ECODE_OK;
}

static void OnLoggingReady(void *arg)
{
    SCOutputRegisterPacketLogger(LOGGER_USER, "custom-packet-logger", CustomPacketLogger,
            CustomPacketLoggerCondition, NULL, ThreadInit, ThreadDeinit);
    SCOutputRegisterFlowLogger(
            "custom-flow-logger", CustomFlowLogger, NULL, ThreadInit, ThreadDeinit);
    SCOutputRegisterTxLogger(LOGGER_USER, "custom-dns-logger", ALPROTO_DNS, CustomDnsLogger, NULL,
            -1, -1, NULL, ThreadInit, ThreadDeinit);
}

static void Init(void)
{
    // Register our callback for when logging is ready.
    SCRegisterOnLoggingReady(OnLoggingReady, NULL);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "CustomLogger",
    .plugin_version = "1.0.0",
    .author = "Firstname Lastname",
    .license = "GPLv2",
    .Init = Init,
};

const SCPlugin *SCPluginRegister(void)
{
    return &PluginRegistration;
}
