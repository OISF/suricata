#include <stdio.h>
#include <stdlib.h>

#include "suricata-plugin.h"
#include "util-mem.h"
#include "util-debug.h"

#define OUTPUT_NAME "template-filetype-plugin"

typedef struct Context_ {
} Context;

static int TemplateWrite(const char *buffer, int buffer_len, void *data) {
    Context *ctx = data;
    printf("TemplateWrite: %s\n", buffer);
    return 0;
}

static void TemplateClose(void *data) {
    Context *ctx = data;
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

static int TemplateOpen(ConfNode *conf, void **data) {
    Context *context = SCCalloc(1, sizeof(Context));
    if (context == NULL) {
        return -1;
    }
    *data = context;
    return 0;
}

/**
 * Called by Suricata to initialize the module. This module registers
 * new file type to the JSON logger.
 */
void TemplateInit(void)
{
    SCPluginFileType *my_output = SCCalloc(1, sizeof(SCPluginFileType));
    my_output->name = OUTPUT_NAME;
    my_output->Open = TemplateOpen;
    my_output->Write = TemplateWrite;
    my_output->Close = TemplateClose;
    if (!SCPluginRegisterFileType(my_output)) {
        FatalError(SC_ERR_PLUGIN, "Failed to register filetype plugin: %s", OUTPUT_NAME);
    }
}

const SCPlugin PluginSpec = {
    .name = OUTPUT_NAME,
    .author = "Some Developer",
    .license = "GPLv2",
    .Init = TemplateInit,
};