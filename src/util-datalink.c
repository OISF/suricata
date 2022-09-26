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
