/* Copyright (C) 2020-2024 Open Information Security Foundation
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

#include "decode.h"
#include "source-pfring.h"
#include "runmode-pfring.h"
#include "util-device.h"

void InitCapturePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    LiveBuildDeviceList("plugin");
    RunModeIdsPfringRegister(plugin_slot);
    TmModuleReceivePfringRegister(receive_slot);
    TmModuleDecodePfringRegister(decode_slot);
}

void SCPluginInit(void)
{
    SCCapturePlugin *plugin = SCCalloc(1, sizeof(SCCapturePlugin));
    if (plugin == NULL) {
        FatalError("Failed to allocate memory for capture plugin");
    }
    plugin->name = "pfring";
    plugin->Init = InitCapturePlugin;
    plugin->GetDefaultMode = RunModeIdsPfringGetDefaultMode;
    SCPluginRegisterCapture(plugin);
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = "pfring",
    .plugin_version = "1.0.0",
    .author = "Open Information Security Foundation",
    .license = "GPLv2",
    .Init = SCPluginInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
