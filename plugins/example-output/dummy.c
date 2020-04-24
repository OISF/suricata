#include <stdio.h>
#include "suricata-plugin.h"
#include "dummy.h"

#define OUTPUT_NAME "plugin:dummy"

typedef struct Context_ {
} Context;

static int dummy_write(const char *buffer, int buffer_len, LogFileCtx *ctx) {
    printf("dummy_write\n");
    printf("dummy_write: rotate=%d\n", ctx->rotation_flag);
    return 0;
}

static void dummy_close(LogFileCtx *ctx) {
    printf("dummy_close\n");
    SCFree(ctx->plugin);
}

static int dummy_open(LogFileCtx *ctx, ConfNode *conf) {
    printf("conf: %p\n", conf);
    Context *context = SCCalloc(1, sizeof(Context));
    ctx->Write = dummy_write;
    ctx->Close = dummy_close;
    ctx->plugin = context;
    return 0;
}

/**
 * Called by Suricata to initialize the module. This module registers
 * new file type to the JSON logger.
 */
void sc_plugin_init(void)
{
    PluginFileType *my_output = SCCalloc(1, sizeof(PluginFileType));
    my_output->name = OUTPUT_NAME;
    my_output->Open = dummy_open;
    RegisterPluginFileType(my_output);
}

/**
 * This function will be called by Suricata after it has loaded the
 * module. Here we register some details of the module as well as the
 * initialization function.
 *
 * This is really just a courtesy by the plugin author where they can
 * register some details of their module and follow a convention we
 * set out.
 */
void sc_plugin_register(SCPlugin *plugin) {
    plugin->name = "dummy-output-plugin";
    plugin->author = "Jason Ish <jason.ish@oisf.net>";
    plugin->license = "GPLv2";
    plugin->Init = sc_plugin_init;
}
