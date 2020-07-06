#include "suricata-plugin.h"

#include "source-pfring.h"
#include "runmode-pfring.h"
#include "util-device.h"

static char *source_name = "pfring-plugin";

void InitSourcePlugin(const char *args, int plugin_slot, int receive_slot, int decode_slot)
{
    LiveBuildDeviceList("pfring");
    RunModeIdsPfringPluginRegister(plugin_slot);
    TmModuleReceivePfringPluginRegister(receive_slot);
    TmModuleDecodePfringPluginRegister(decode_slot);
}

void SCPluginInit(void)
{
    SCLogNotice("SCPluginInit");
    SourcePlugin *plugin = SCCalloc(1, sizeof(SourcePlugin));
    if (plugin == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for source plugin");
    }
    plugin->name = source_name;
    plugin->Init = InitSourcePlugin;
    plugin->GetDefaultMode = RunModeIdsPfringPluginGetDefaultMode;
    SCPluginRegisterSource(plugin);
}

const SCPlugin PluginSpec = {
    .name = "source-pfring",
    .author = "Some Developer",
    .license = "GPLv2",
    .Init = SCPluginInit,
};