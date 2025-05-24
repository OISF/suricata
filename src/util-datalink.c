/* Copyright (C) 2021 Open Information Security Foundation
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
#include "util-datalink.h"
#include "rust.h"
#include "decode.h"

int g_datalink_value = LINKTYPE_NULL;
int g_datalink_is_multiple = 0;

void DatalinkSetGlobalType(int datalink)
{
    if (g_datalink_value != LINKTYPE_NULL) {
        if (datalink != g_datalink_value) {
            g_datalink_is_multiple = 1;
        }
    } else {
        g_datalink_value = datalink;
    }
}

inline int DatalinkGetGlobalType(void)
{
    return g_datalink_value;
}

bool DatalinkHasMultipleValues(void)
{
    return g_datalink_is_multiple == 1;
}

static void *datalink_value_map;

void DatalinkTableInit(void)
{
    datalink_value_map = SCDatalinkInit();
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_NULL, "NULL");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_ETHERNET, "EN10MB");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_LINUX_SLL, "LINUX_SLL");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_LINUX_SLL2, "LINUX_SLL2");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_PPP, "PPP");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_RAW, "RAW");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_RAW2, "RAW2");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_GRE_OVER_IP, "GRE_RAW");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_NULL, "NULL");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_CISCO_HDLC, "C_HDLC");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_IPV4, "IPv4");
    SCDatalinkValueNameInsert(datalink_value_map, LINKTYPE_IPV6, "IPv6");
}

void DatalinkTableDeinit(void)
{
    SCDatalinkDeInit(datalink_value_map);
}

const char *DatalinkValueToName(int datalink_value)
{
    return SCDatalinkValueToName(datalink_value_map, datalink_value);
}
